;;;; secret.lisp — every operation that takes a secp256k1 private key.
;;;;
;;;; The rule (see the FIXED library): a secret lives only in fixed memory.  So here
;;;;   - a private key is a fixed 32-byte buffer, and every entry point says so with
;;;;     FIXED:CHECK-FIXED -- an integer or a heap copy is refused at the boundary;
;;;;   - scalars mod n are 8 x 32-bit words in fixed fixnum arrays ("sw"); byte
;;;;     conversion, add, negate, select and range checks are written once here,
;;;;     branch-free, and only the Montgomery multiply and inverse go through the
;;;;     backend's field limbs;
;;;;   - k*G and k*P reuse ct.lisp's constant-time ladders, fed nibbles from a fixed
;;;;     array, and ECDH's result goes from the limbs into a fixed output buffer -- no
;;;;     secret ever becomes a Lisp integer;
;;;;   - WITH-SECRET-SCRATCH binds every scratch buffer the field, Montgomery and
;;;;     constant-time code touches to fixed buffers from the pool and wipes them on
;;;;     exit, and inside it the per-call fresh-scratch wrappers keep those buffers
;;;;     rather than allocating heap ones;
;;;;   - hashing of secret material (BIP-340 nonces, RFC 6979) goes through natrium's
;;;;     streaming SHA-256 / HMAC with fixed outputs.
;;;; Public results (public keys, R, signatures) are returned as ordinary values.
;;;;
;;;; Loaded only on the limb backends (SBCL x86-64/arm64, modus with %mul-split): with
;;;; no constant-time multiply there is no way to sign without leaking, so elsewhere
;;;; the signing functions do not exist.

(in-package #:secp256k1-fast)

;;; ---------------------------------------------------------------------------
;;; The secret scope.
;;; ---------------------------------------------------------------------------

#-modus-mul-split
(progn
(eval-when (:compile-toplevel :load-toplevel :execute)
(defparameter +secret-scratch-specs+
  ;; (special kind length): every module-level buffer that secret arithmetic writes.
  (append
   '((*fmul-scratch* :ub64 8) (*mont-scratch* :ub64 9)
     (*nba* :fixnums 136) (*nbb* :fixnums 136) (*nbc* :fixnums 136) (*nbd* :fixnums 136))
   (mapcar (lambda (s) (list s :ub64 4))
           '(*inv-r* *ivx2* *ivx3* *ivx6* *ivx9* *ivx11* *ivx22* *ivx44* *ivx88* *ivx176*
             *ivx220* *ivx223* *tA* *tB* *tC* *tD* *tE* *tF* *tG*
             *aZZ* *aU2* *aS2* *aH* *aRR* *aHH* *aI* *aJ* *aV* *aT*
             *gx* *gy* *gz* *wx* *wy* *wz* *q2x* *q2lx* *q2y* *q2ny*
             *n-acc* *n-base* *n-out*
             *ct-t0* *ct-t1* *ct-t2* *ct-t3* *ct-t4* *ct-selx* *ct-sely* *ct-selz*
             *ct-ax* *ct-ay* *ct-az* *ct-sx* *ct-sy* *ct-sz* *ct-zinv* *ct-rx* *ct-ry*)))))

(defmacro with-secret-scratch (&body body)
  "Run BODY with every scratch buffer bound to a fixed buffer, wiped on exit."
  (let ((specs +secret-scratch-specs+))
    `(let (,@(loop for (sym kind n) in specs collect `(,sym (gossamer:acquire ,kind ,n)))
           (*secret-scope* t))
       (unwind-protect (progn ,@body)
         ,@(loop for (sym kind n) in specs collect `(gossamer:release ,kind ,n ,sym))))))

(defun %fe-scratch () (gossamer:acquire :ub64 4))
(defun %fe-release (fe) (gossamer:release :ub64 4 fe))

(defun %sw->fe! (fe w)
  "Scalar words W (8 x u32, little-endian) -> 4 x u64 limbs."
  (declare (type (simple-array (unsigned-byte 64) (4)) fe) (type (simple-array fixnum (8)) w)
           (optimize (speed 3) (safety 0)))
  (dotimes (i 4 fe)
    (setf (aref fe i) (logior (the (unsigned-byte 32) (aref w (* 2 i)))
                              (the (unsigned-byte 64) (ash (the (unsigned-byte 32) (aref w (1+ (* 2 i)))) 32))))))

(defun %fe->sw! (w fe)
  (declare (type (simple-array (unsigned-byte 64) (4)) fe) (type (simple-array fixnum (8)) w)
           (optimize (speed 3) (safety 0)))
  (dotimes (i 4 w)
    (let ((l (aref fe i)))
      (setf (aref w (* 2 i)) (logand l #xFFFFFFFF)
            (aref w (1+ (* 2 i))) (ash l -32)))))
)

#+modus-mul-split
(progn
;; modus has no fixed-memory backend yet (FIXED-BACKEND is :NONE), so the scope is
;; the per-call fresh scratch plus a wipe of every buffer on exit.
(defparameter +secret-wipe-specials+
  '(*ct-t0* *ct-t1* *ct-t2* *ct-t3* *ct-t4* *ct-selx* *ct-sely* *ct-selz*
    *ct-ax* *ct-ay* *ct-az* *ct-sx* *ct-sy* *ct-sz* *ct-zinv* *ct-rx* *ct-ry*
    *n-acc* *n-base* *n-out*))

(defmacro with-secret-scratch (&body body)
  `(with-fresh-ct-scratch
     (let ((*secret-scope* t))
       (unwind-protect (progn ,@body)
         (dolist (s +secret-wipe-specials+)
           (let ((v (symbol-value s))) (when (arrayp v) (fill v 0))))))))

(defun %fe-scratch () (mkfe))
(defun %fe-release (fe) (fill fe 0))

(defun %repack! (dst dw src sw total-bits)
  "Little-endian limbs of SW bits in SRC -> limbs of DW bits in DST, TOTAL-BITS long.
Every branch depends on bit positions only, never on the values."
  (dotimes (k (ceiling total-bits dw) dst)
    (let ((val 0) (bit (* k dw)) (got 0))
      (loop while (and (< got dw) (< bit total-bits)) do
        (let* ((si (floor bit sw)) (off (mod bit sw))
               (take (min (- sw off) (- dw got)))
               (piece (logand (ash (aref src si) (- off)) (1- (ash 1 take)))))
          (setf val (logior val (ash piece got)))
          (incf got take) (incf bit take)))
      (setf (aref dst k) val))))

(defun %sw->fe! (fe w) (%repack! fe 52 w 32 256))
(defun %fe->sw! (w fe) (%repack! w 32 fe 52 256))
)

;;; ---------------------------------------------------------------------------
;;; Scalars mod n as 8 x 32-bit words.  Every function is branch-free in the values.
;;; ---------------------------------------------------------------------------

(defparameter +n-words+
  (let ((v (make-array 8 :element-type 'fixnum)) (n #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141))
    (dotimes (i 8 v) (setf (aref v i) (ldb (byte 32 (* 32 i)) n)))))

(defun %sw-load! (w bytes &optional (off 0))
  "W <- the 32 big-endian bytes BYTES[OFF, OFF+32)."
  (dotimes (i 8 w)
    (let ((j (+ off (- 28 (* 4 i)))))
      (setf (aref w i) (logior (ash (aref bytes j) 24) (ash (aref bytes (+ j 1)) 16)
                               (ash (aref bytes (+ j 2)) 8) (aref bytes (+ j 3)))))))

(defun %sw-store! (bytes w &optional (off 0))
  (dotimes (i 8 bytes)
    (let ((j (+ off (- 28 (* 4 i)))) (x (aref w i)))
      (setf (aref bytes j) (ldb (byte 8 24) x) (aref bytes (+ j 1)) (ldb (byte 8 16) x)
            (aref bytes (+ j 2)) (ldb (byte 8 8) x) (aref bytes (+ j 3)) (ldb (byte 8 0) x)))))

(defun %sw-sub-n! (out a)
  "OUT <- A - n mod 2^256.  Returns the final borrow: 1 iff A < n."
  (let ((borrow 0))
    (dotimes (i 8 borrow)
      (let ((d (- (aref a i) (aref +n-words+ i) borrow)))
        (setf (aref out i) (logand d #xFFFFFFFF)
              borrow (logand (ash d -32) 1))))))

(defun %sw-select! (out mask a b)
  "OUT <- A if MASK is #xFFFFFFFF, B if MASK is 0."
  (dotimes (i 8 out)
    (setf (aref out i) (logxor (aref b i) (logand mask (logxor (aref a i) (aref b i)))))))

(defun %sw-or (w) (let ((x 0)) (dotimes (i 8 x) (setf x (logior x (aref w i))))))

(defun %sw-reduce! (w tmp)
  "W <- W mod n, for W < 2^256 (< 2n), using TMP (8 words) as scratch."
  (let* ((lt (%sw-sub-n! tmp w))             ; 1 iff W < n
         (keep (logand (- lt) #xFFFFFFFF)))
    (%sw-select! w keep w tmp)))

(defun %sw-valid-key-p (w tmp)
  "True iff 0 < W < n.  (The answer is public: an invalid key is refused.)"
  (and (= 1 (%sw-sub-n! tmp w)) (/= 0 (%sw-or w))))

(defun %sw-add-mod-n! (out a b tmp)
  "OUT <- A + B mod n for A, B < n."
  (let ((carry 0))
    (dotimes (i 8)
      (let ((s (+ (aref a i) (aref b i) carry)))
        (setf (aref out i) (logand s #xFFFFFFFF) carry (ash s -32))))
    ;; keep the sum iff it did not carry out of 256 bits and is < n
    (let* ((lt (%sw-sub-n! tmp out))
           (keep (logand (- (logand lt (logxor carry 1))) #xFFFFFFFF)))
      (%sw-select! out keep out tmp))))

(defun %sw-cneg! (w bit tmp)
  "W <- n - W if BIT is 1, W if BIT is 0 (for 0 < W < n)."
  (let ((borrow 0))
    (dotimes (i 8)
      (let ((d (- (aref +n-words+ i) (aref w i) borrow)))
        (setf (aref tmp i) (logand d #xFFFFFFFF) borrow (logand (ash d -32) 1)))))
  (%sw-select! w (logand (- bit) #xFFFFFFFF) tmp w))

(defun %sw-nibbles! (nib w)
  "The 64 base-16 digits of W, index = window number (ct.lisp's ordering)."
  (dotimes (i 64 nib)
    (setf (aref nib i) (logand (ash (aref w (floor i 8)) (* -4 (mod i 8))) 15))))

(defun %sw-mul-mod-n! (out a b)
  "OUT <- A * B mod n (constant-time Montgomery)."
  (let ((fa (%fe-scratch)) (fb (%fe-scratch)) (ft (%fe-scratch)))
    (unwind-protect
         (progn (%sw->fe! fa a) (%sw->fe! fb b)
                (nmul! ft fa *nR2*)          ; a*R
                (nmul! fa ft fb)             ; (a*R)*b*R^-1 = a*b
                (%fe->sw! out fa))
      (%fe-release fa) (%fe-release fb) (%fe-release ft))))

(defun %sw-inv-mod-n! (out a)
  "OUT <- A^-1 mod n for 0 < A < n (Fermat chain over a public exponent)."
  (let ((fa (%fe-scratch)) (fo (%fe-scratch)))
    (unwind-protect (progn (%sw->fe! fa a) (n-inv! fo fa) (%fe->sw! out fo))
      (%fe-release fa) (%fe-release fo))))

(defun %fe-store! (bytes fe w)
  "The canonical field element FE as 32 big-endian bytes into BYTES, via words W."
  (%fe->sw! w fe) (%sw-store! bytes w))

(defun %fe-odd-p (fe w) (%fe->sw! w fe) (logand (aref w 0) 1))

(defun %check-seckey (seckey)
  (gossamer:check-fixed seckey "secp256k1 private key")
  (unless (= (length seckey) 32) (error "secp256k1 private key must be 32 bytes, got ~a" (length seckey)))
  seckey)

(defmacro %with-key-words ((w tmp seckey) &body body)
  "Bind W to SECKEY's scalar words (fixed) and TMP to scratch words; refuse a key
outside [1, n-1]."
  `(gossamer:with-fixed-scratch ((,w :fixnums 8) (,tmp :fixnums 8))
     (%sw-load! ,w (%check-seckey ,seckey))
     (unless (%sw-valid-key-p ,w ,tmp) (error "invalid secp256k1 private key (0 or >= n)"))
     ,@body))

;;; ---------------------------------------------------------------------------
;;; Public keys.
;;; ---------------------------------------------------------------------------

(defun %mul-g-words (w nib)
  "k*G for scalar words W into *CT-RX*/*CT-RY* (inside a secret scope).  Returns T
for infinity."
  (%sw-nibbles! nib w)
  (%ct-mul-g-nib nib))

(defun secp-pubkey (seckey)
  "The public key point (x . y) for SECKEY, a fixed 32-byte private key.  For a
PUBLIC scalar use (SECP-MUL-POINT k (SECP-GENERATOR))."
  (when (integerp seckey)
    (error "SECP-PUBKEY takes a fixed 32-byte private key; for a public scalar use SECP-MUL-POINT"))
  (with-secret-scratch
    (%with-key-words (w tmp seckey)
      (gossamer:with-fixed-scratch ((nib :fixnums 64))
        (%mul-g-words w nib)
        (cons (f->i *ct-rx*) (f->i *ct-ry*))))))

;;; ---------------------------------------------------------------------------
;;; Key arithmetic for HD derivation (BIP-32), on fixed buffers.
;;; ---------------------------------------------------------------------------

(defun seckey-valid-p (seckey)
  "True iff SECKEY (fixed 32 bytes) is in [1, n-1]."
  (gossamer:with-fixed-scratch ((w :fixnums 8) (tmp :fixnums 8))
    (%sw-load! w (%check-seckey seckey))
    (%sw-valid-key-p w tmp)))

(defun seckey-tweak-add-into (seckey tweak32 out &key (tweak-start 0))
  "OUT <- SECKEY + TWEAK mod n, all fixed 32-byte buffers (TWEAK32[TWEAK-START,+32)
may be a slice of a larger fixed buffer, e.g. the left half of a BIP-32 HMAC).
Signals if TWEAK >= n or the result is 0 -- BIP-32's 'proceed with the next index'
cases.  OUT may be SECKEY."
  (%check-seckey seckey) (gossamer:check-fixed tweak32 "secp256k1 tweak") (gossamer:check-fixed out "secp256k1 tweak result")
  (gossamer:with-fixed-scratch ((a :fixnums 8) (b :fixnums 8) (tmp :fixnums 8))
    (%sw-load! a seckey)
    (%sw-load! b tweak32 tweak-start)
    (unless (= 1 (%sw-sub-n! tmp b)) (error "secp256k1 tweak is not below n"))
    (%sw-add-mod-n! a a b tmp)
    (when (zerop (%sw-or a)) (error "secp256k1 tweak-add gives zero"))
    (%sw-store! out a)))

(defun seckey-negate-into (seckey out &key (negate t))
  "OUT <- n - SECKEY when NEGATE (a public decision, e.g. the parity of the public
key's Y), else a copy of SECKEY.  Fixed 32-byte buffers; OUT may be SECKEY.  The
operation is the same either way, so NEGATE is not visible in timing."
  (gossamer:check-fixed out "secp256k1 negate result")
  (%with-key-words (w tmp seckey)
    (%sw-cneg! w (if negate 1 0) tmp)
    (%sw-store! out w)))

(defun seckey-tweak-mul-into (seckey tweak32 out &key (tweak-start 0))
  "OUT <- SECKEY * TWEAK mod n (constant-time Montgomery), fixed 32-byte buffers; OUT
may be SECKEY.  TWEAK may be secret too (e.g. a blinding factor).  Signals if TWEAK
is 0 or >= n (the product would not be a key)."
  (%check-seckey seckey) (gossamer:check-fixed tweak32 "secp256k1 tweak") (gossamer:check-fixed out "secp256k1 tweak result")
  (gossamer:with-fixed-scratch ((a :fixnums 8) (b :fixnums 8) (tmp :fixnums 8))
    (%sw-load! a seckey)
    (%sw-load! b tweak32 tweak-start)
    (unless (%sw-valid-key-p b tmp) (error "secp256k1 multiplicative tweak is 0 or not below n"))
    (%sw-mul-mod-n! a a b)
    (%sw-store! out a)))

(defun seckey-add-into (a b out)
  "OUT <- A + B mod n for two secret keys (fixed 32-byte buffers); OUT may be A or B.
Signals if the sum is zero."
  (seckey-tweak-add-into a (%check-seckey b) out))

(defun seckey-compressed-pubkey (seckey)
  "The 33-byte compressed SEC1 public key of SECKEY (fixed 32 bytes)."
  (let ((pt (secp-pubkey seckey)) (out (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref out 0) (if (oddp (secp-y pt)) 3 2))
    (replace out (int-to-bytes32 (secp-x pt)) :start1 1)
    out))

;;; ---------------------------------------------------------------------------
;;; Tagged hashes (BIP-340) streamed into fixed outputs.
;;; ---------------------------------------------------------------------------

(defvar *tag-hashes* (make-hash-table :test 'equal))
(defun %tag-hash (tag)
  (or (gethash tag *tag-hashes*)
      (setf (gethash tag *tag-hashes*) (natrium:sha256 (sha:ascii->bytes tag)))))
(%tag-hash "BIP0340/aux") (%tag-hash "BIP0340/nonce") (%tag-hash "BIP0340/challenge")

(defun %tagged-into (tag parts out)
  (let ((th (%tag-hash tag)))
    (natrium:with-sha256 (c)
      (natrium:sha256-update c th) (natrium:sha256-update c th)
      (dolist (p parts) (natrium:sha256-update c p))
      (natrium:sha256-final-into c out))))

;;; ---------------------------------------------------------------------------
;;; BIP-340.
;;; ---------------------------------------------------------------------------

(defun secp256k1-fast.schnorr:pubkey-xonly (seckey)
  "32-byte x-only public key of SECKEY (fixed 32 bytes)."
  (let ((out (make-array 32 :element-type '(unsigned-byte 8))))
    (with-secret-scratch
      (%with-key-words (w tmp seckey)
        (gossamer:with-fixed-scratch ((nib :fixnums 64))
          (%mul-g-words w nib)
          (%fe-store! out *ct-rx* tmp))))
    out))

(defvar +zero32+ (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(defun secp256k1-fast.schnorr:schnorr-sign (seckey msg &optional (aux +zero32+))
  "BIP-340 signature (64 bytes) of MSG (any length; 32 bytes is the usual hash) under
SECKEY, a fixed 32-byte private key.
AUX is the 32-byte auxiliary randomness (zeros by default, as BIP-340 permits;
pass fresh random bytes for side-channel hardening)."
  (unless (= (length aux) 32) (error "BIP-340 aux must be 32 bytes"))
  (let ((sig (make-array 64 :element-type '(unsigned-byte 8))))
    (with-secret-scratch
      (%with-key-words (d tmp seckey)
        (gossamer:with-fixed-scratch ((nib :fixnums 64) (k :fixnums 8) (e :fixnums 8) (s :fixnums 8)
                                   (px :octets 32) (rx :octets 32) (tb :octets 32) (ah :octets 32)
                                   (rnd :octets 32) (eb :octets 32))
          (%mul-g-words d nib)                                 ; P = d*G
          (%fe-store! px *ct-rx* tmp)
          (%sw-cneg! d (%fe-odd-p *ct-ry* tmp) tmp)            ; d <- n-d if P.y odd
          (%tagged-into "BIP0340/aux" (list aux) ah)
          (%sw-store! tb d)
          (dotimes (i 32) (setf (aref tb i) (logxor (aref tb i) (aref ah i))))
          (%tagged-into "BIP0340/nonce" (list tb px msg) rnd)
          (%sw-load! k rnd) (%sw-reduce! k tmp)
          (when (zerop (%sw-or k)) (error "BIP-340: nonce is zero"))
          (%mul-g-words k nib)                                 ; R = k*G
          (%fe-store! rx *ct-rx* tmp)
          (%sw-cneg! k (%fe-odd-p *ct-ry* tmp) tmp)            ; k <- n-k if R.y odd
          (%tagged-into "BIP0340/challenge" (list rx px msg) eb)
          (%sw-load! e eb) (%sw-reduce! e tmp)                 ; e (public)
          (%sw-mul-mod-n! s e d)
          (%sw-add-mod-n! s s k tmp)                           ; s = k + e*d
          (replace sig rx)
          (%sw-store! sig s 32))))
    sig))

;;; ---------------------------------------------------------------------------
;;; ECDSA with RFC 6979 nonces.
;;; ---------------------------------------------------------------------------

(defun rfc6979-k-into (seckey hash32 k-words)
  "RFC 6979 §3.2 nonce for SECKEY and HASH32 into K-WORDS (fixed).  The DRBG state,
the key and h1 are fixed buffers."
  (gossamer:with-fixed-scratch ((kk :octets 32) (v :octets 32) (h1 :octets 32) (z :fixnums 8)
                             (tmp :fixnums 8) (b0 :octets 1) (b1 :octets 1))
    (%sw-load! z hash32) (%sw-reduce! z tmp) (%sw-store! h1 z)    ; bits2octets
    (fill v 1) (setf (aref b1 0) 1)
    (natrium:hmac-sha256-into kk (list v b0 seckey h1) kk)
    (natrium:hmac-sha256-into kk v v)
    (natrium:hmac-sha256-into kk (list v b1 seckey h1) kk)
    (natrium:hmac-sha256-into kk v v)
    (loop
      (natrium:hmac-sha256-into kk v v)
      (%sw-load! k-words v)
      (when (%sw-valid-key-p k-words tmp) (return k-words))
      (natrium:hmac-sha256-into kk (list v b0) kk)
      (natrium:hmac-sha256-into kk v v))))

(defun rfc6979-k (seckey hash32)
  "The RFC 6979 nonce as an INTEGER -- for test vectors only: a real nonce must not
leave fixed memory."
  (gossamer:with-fixed-scratch ((k :fixnums 8) (b :octets 32))
    (rfc6979-k-into (%check-seckey seckey) hash32 k)
    (%sw-store! b k)
    (bytes-to-int b)))

(defun ecdsa-sign-raw (seckey hash32)
  "Sign HASH32 under SECKEY (fixed 32 bytes).  Returns (values r s v): S low-S
(BIP-62), V the 0/1 recovery id.  NIL in the (negligible) r = 0 or s = 0 cases."
  (secp-init)
  (with-secret-scratch
    (%with-key-words (d tmp seckey)
      (gossamer:with-fixed-scratch ((nib :fixnums 64) (k :fixnums 8) (kinv :fixnums 8) (z :fixnums 8)
                                 (r :fixnums 8) (s :fixnums 8) (rb :octets 32) (sb :octets 32))
        (rfc6979-k-into seckey hash32 k)
        (%mul-g-words k nib)                                     ; R = k*G
        (let* ((n *secp256k1-n*)
               (rx (f->i *ct-rx*)) (ry-odd (oddp (f->i *ct-ry*)))
               (rint (mod rx n)))                                ; r is public
          (when (zerop rint) (return-from ecdsa-sign-raw nil))
          (%sw-load! r (int-to-bytes32 rint))
          (%sw-load! z hash32) (%sw-reduce! z tmp)
          (%sw-inv-mod-n! kinv k)
          (%sw-mul-mod-n! s r d)                                 ; r*d
          (%sw-add-mod-n! s s z tmp)                             ; z + r*d
          (%sw-mul-mod-n! s kinv s)                              ; k^-1 (z + r*d)
          (%sw-store! sb s)
          (let ((sint (bytes-to-int sb)))                        ; s is public
            (when (zerop sint) (return-from ecdsa-sign-raw nil))
            (let* ((high-s (> sint (ash n -1)))
                   (v0 (if ry-odd 1 0)))
              (values rint (if high-s (- n sint) sint) (if high-s (logxor v0 1) v0)))))))))

;;; ---------------------------------------------------------------------------
;;; ECDH.
;;; ---------------------------------------------------------------------------

(in-package #:secp256k1-fast.ecdh)

(defstruct (keypair (:constructor %make-keypair (secret public)))
  secret     ; a fixed 32-byte private key
  public)    ; affine point (public)

(defun keypair-from-secret (secret-bytes)
  "Keypair from a 32-byte big-endian secret, copied into a POOLED fixed buffer;
release it with KEYPAIR-WIPE.  A caller that read the secret from somewhere (a file,
a socket) wipes its own copy.  Errors on 0 or >= n, as `SecretKey::from_slice` does."
  (unless (= (length secret-bytes) 32) (error "invalid secp256k1 secret key"))
  (let ((sk (gossamer:pooled-copy secret-bytes)))
    (handler-case (gossamer:own (%make-keypair sk (secp256k1-fast:secp-pubkey sk)) sk)
      (error (e) (gossamer:free sk) (error e)))))

(defun keypair-public-bytes (kp) (encode-pubkey (keypair-public kp)))

(defun keypair-wipe (kp)
  "Wipe KP's secret and return its buffer to the pool.  KP's secret becomes NIL: the
buffer may next hold someone else's key, so nothing may keep using it."
  (when (keypair-secret kp)
    (gossamer:disown kp)
    (gossamer:free (keypair-secret kp))
    (setf (keypair-secret kp) nil))
  kp)

(defun ecdh-x (secret point out &key (start 0))
  "Write the 32-byte X coordinate of SECRET * POINT into OUT at START -- OUT should be
fixed, since it is the shared secret.  SECRET is a KEYPAIR or a fixed 32-byte key.
Refuses a POINT that is not on the curve (an invalid-curve attack recovers the secret
from such answers) and the point at infinity."
  (unless (peer-point-valid-p point) (error "ECDH peer point is not a point on secp256k1"))
  (let ((sk (if (keypair-p secret) (keypair-secret secret) secret)))
    (secp256k1-fast::with-secret-scratch
      (secp256k1-fast::%with-key-words (w tmp sk)
        (gossamer:with-fixed-scratch ((nib :fixnums 64) (xb :octets 32))
          (secp256k1-fast::%sw-nibbles! nib w)
          (when (secp256k1-fast::%ct-mul-point-nib nib point) (error "ECDH produced the point at infinity"))
          (secp256k1-fast::%fe-store! xb secp256k1-fast::*ct-rx* tmp)
          (replace out xb :start1 start))))
    out))

(defun ecdh-compressed-into (secret point out &key (start 0))
  "Write the 33-byte compressed SEC1 encoding of SECRET * POINT into OUT at START
(OUT fixed: it is the shared secret).  For protocols that hash the whole point --
BOLT 4/8 ECDH is SHA-256 of exactly this.  Same refusals as ECDH-X."
  (unless (peer-point-valid-p point) (error "ECDH peer point is not a point on secp256k1"))
  (let ((sk (if (keypair-p secret) (keypair-secret secret) secret)))
    (secp256k1-fast::with-secret-scratch
      (secp256k1-fast::%with-key-words (w tmp sk)
        (gossamer:with-fixed-scratch ((nib :fixnums 64) (xb :octets 32))
          (secp256k1-fast::%sw-nibbles! nib w)
          (when (secp256k1-fast::%ct-mul-point-nib nib point) (error "ECDH produced the point at infinity"))
          (secp256k1-fast::%fe-store! xb secp256k1-fast::*ct-rx* tmp)
          (setf (aref out start) (+ 2 (secp256k1-fast::%fe-odd-p secp256k1-fast::*ct-ry* tmp)))
          (replace out xb :start1 (1+ start)))))
    out))

(defun noise-dh (keypair point out &key (start 0))
  "The FIPS Noise DH (handshake.rs `fn ecdh`): SHA-256(x(secret * point)) into OUT."
  (gossamer:with-fixed-scratch ((x :octets 32))
    (ecdh-x keypair point x)
    (natrium:sha256-into x out :start start)))
