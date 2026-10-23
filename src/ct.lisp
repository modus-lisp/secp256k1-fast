;;;; ct.lisp — constant-time scalar multiplication of the base point G.
;;;;
;;;; For SECRET scalars (key generation, ECDSA/Schnorr nonces) we never multiply
;;;; by an attacker-chosen point — only by the fixed generator G.  This file gives
;;;; a constant-time k*G that overrides the variable-time CT-MUL-G fallback on the
;;;; limb (VOP) backend, where the field ops (fmul!/fadd!/fsub!) are already
;;;; branchless.  The variable-time GLV+wNAF path stays in use for verification
;;;; (all-public inputs) — exactly libsecp256k1's ecmult_gen / ecmult split.
;;;;
;;;; Technique:
;;;;   - complete (exception-free) projective addition (Renes-Costello-Batina
;;;;     2016, a=0): one unified formula used for BOTH adds and doublings, so
;;;;     there are no secret-dependent branches and no special cases;
;;;;   - a fixed 4-bit window over all 64 nibbles of the 256-bit scalar (constant
;;;;     256 doublings + 64 additions regardless of the scalar);
;;;;   - a constant-time table read: every window scans all 16 entries and ORs in
;;;;     each limb ANDed with an all-ones-or-zero mask, so the secret nibble never
;;;;     indexes memory or reaches a branch.
;;;;
;;;; Constant-time *at the algorithm + field-arithmetic level on the VOP backend*.
;;;; In a GC'd runtime this is not a formal microarchitectural guarantee (GC,
;;;; compiler), but it removes the exploitable algorithmic / cache channels.

(in-package #:secp256k1-fast)

;;; Homogeneous projective point = three FEs (X:Y:Z) meaning affine (X/Z, Y/Z);
;;; identity = (0:1:0).  All scratch is module-level (single-threaded fast path,
;;; matching field-limb.lisp).

(defvar *ct-b3* (i->fe 21))            ; 3*b, b=7
(defvar *ct-t0* (mkfe)) (defvar *ct-t1* (mkfe)) (defvar *ct-t2* (mkfe))
(defvar *ct-t3* (mkfe)) (defvar *ct-t4* (mkfe))

(defun ct-cadd! (ox oy oz x1 y1 z1 x2 y2 z2)
  "Complete projective addition (a=0): (ox:oy:oz) <- (x1:y1:z1) + (x2:y2:z2).
The output FEs must be distinct from the inputs; valid for all points, including
P=Q and the identity (so it doubles too)."
  (declare (type fe ox oy oz x1 y1 z1 x2 y2 z2) (optimize (speed 3) (safety 0)))
  (let ((t0 *ct-t0*) (t1 *ct-t1*) (t2 *ct-t2*) (t3 *ct-t3*) (t4 *ct-t4*) (b3 *ct-b3*))
    (fmul! t0 x1 x2) (fmul! t1 y1 y2) (fmul! t2 z1 z2)
    (fadd! t3 x1 y1) (fadd! t4 x2 y2) (fmul! t3 t3 t4)
    (fadd! t4 t0 t1) (fsub! t3 t3 t4) (fadd! t4 y1 z1)
    (fadd! ox y2 z2) (fmul! t4 t4 ox) (fadd! ox t1 t2)
    (fsub! t4 t4 ox) (fadd! ox x1 z1) (fadd! oy x2 z2)
    (fmul! ox ox oy) (fadd! oy t0 t2) (fsub! oy ox oy)
    (fadd! ox t0 t0) (fadd! t0 ox t0) (fmul! t2 b3 t2)
    (fadd! oz t1 t2) (fsub! t1 t1 t2) (fmul! oy b3 oy)
    (fmul! ox t4 oy) (fmul! t2 t3 t1) (fsub! ox t2 ox)
    (fmul! oy oy t0) (fmul! t1 t1 oz) (fadd! oy t1 oy)
    (fmul! t0 t0 t3) (fmul! oz oz t4) (fadd! oz oz t0)))

;;; precomputed table: T[i] = i*G as a projective point, i = 0..15.
(defvar *ct-gtab* nil)

(defun %ct-table ()
  (or *ct-gtab*
      (setf *ct-gtab*
            (let ((tab (make-array 16)))
              (dotimes (i 16 tab)
                (let ((p (if (zerop i) *secp256k1-infinity* (secp-mul-point i (secp-generator)))))
                  (setf (aref tab i)
                        (if (secp-inf-p p)
                            (vector (i->fe 0) (i->fe 1) (i->fe 0))             ; identity
                            (vector (i->fe (secp-x p)) (i->fe (secp-y p)) (i->fe 1))))))))))

(declaim (inline %ct-eq))
(defun %ct-eq (a b)
  "1 if small non-negative fixnums A=B, else 0 — branchlessly."
  (declare (type fixnum a b))
  (let ((x (logxor a b)))                    ; 0 iff equal
    (- 1 (logand (ash (logior x (- x)) -62) 1))))

(defvar *ct-selx* (mkfe)) (defvar *ct-sely* (mkfe)) (defvar *ct-selz* (mkfe))

(defvar *ct-gtab-flat* nil)

(defun %ct-gtab-flat ()
  "*CT-GTAB* flattened to %CT-SELECT-TAB's layout: entry i's X Y Z at 3i..3i+2."
  (or *ct-gtab-flat*
      (setf *ct-gtab-flat*
            (let ((flat (make-array 48)) (tab (%ct-table)))
              (dotimes (i 16 flat)
                (dotimes (c 3) (setf (svref flat (+ (* 3 i) c)) (aref (aref tab i) c))))))))

(defun %ct-select (digit)
  "Constant-time read of table entry DIGIT into (*ct-selx* *ct-sely* *ct-selz*):
scan all 16 and OR in each limb ANDed with mask = all-ones iff i = DIGIT
(%CT-SELECT-TAB).  It used to MULTIPLY each entry by a 0/1 field flag and add:
the same constant-time shape at 48 field multiplies a read, which on modus was a
third of CT-MUL-G."
  (%ct-select-tab (%ct-gtab-flat) digit *ct-selx* *ct-sely* *ct-selz*))

(defvar *ct-ax* (mkfe)) (defvar *ct-ay* (mkfe)) (defvar *ct-az* (mkfe))
(defvar *ct-sx* (mkfe)) (defvar *ct-sy* (mkfe)) (defvar *ct-sz* (mkfe))
(defvar *ct-zinv* (mkfe)) (defvar *ct-rx* (mkfe)) (defvar *ct-ry* (mkfe))

#-modus-mul-split
(defun %ct-nibbles (k)
  "The 64 base-16 digits of K (0 <= K < 2^256), index = window number.  K is
converted to a fixed 4-limb form ONCE (via i->fe); the per-nibble slicing then
runs on 32-bit fixnum halves, so it does the same work for every scalar rather
than touching the secret bignum 64 times (which would leak its magnitude)."
  (let ((kf (i->fe k)) (d (make-array 64 :element-type 'fixnum)))
    (declare (type fe kf) (type (simple-array fixnum (64)) d))
    (dotimes (i 4 d)
      (let ((lo (logand (aref kf i) #xFFFFFFFF))     ; low 32 bits  (fixnum)
            (hi (ash (aref kf i) -32)))              ; high 32 bits (fixnum)
        (declare (type (unsigned-byte 32) lo hi))
        (dotimes (j 8)
          (setf (aref d (+ (* i 16) j))      (logand (ash lo (* -4 j)) 15)
                (aref d (+ (* i 16) 8 j))    (logand (ash hi (* -4 j)) 15)))))))

#+modus-mul-split
(defun %ct-nibbles (k)
  "The 64 base-16 digits of K (0 <= K < 2^256), index = window number.  As on
SBCL: K becomes fixed limbs ONCE (2^256 added first so the bignum the limbs are
peeled from has the same length for every K), then the slicing is fixnum work."
  (%ct-fe-nibbles (i->fe (+ k *ct-2^256*))))

(defun %ct-mul-g-nib (nib)
  "Constant-time digits*G for NIB, the scalar's 64 base-16 digits (index = window).
Returns T when the result is the point at infinity; otherwise leaves the affine
result in *CT-RX* / *CT-RY* (FEs) and returns NIL -- so a caller whose result is
itself secret (none today for k*G, but see %CT-MUL-POINT-NIB) never has to make it
an integer."
  (declare (type (simple-array fixnum (64)) nib))
  (secp-init)
  (let ((ax *ct-ax*) (ay *ct-ay*) (az *ct-az*)
        (sx *ct-sx*) (sy *ct-sy*) (sz *ct-sz*))
    (i->fe! ax 0) (i->fe! ay 1) (i->fe! az 0)        ; accumulator = identity
    (loop for w fixnum from 63 downto 0 do
      (dotimes (i 4)                                   ; acc <- 16*acc (four doublings)
        (ct-cadd! sx sy sz  ax ay az  ax ay az)
        (fcopy! ax sx) (fcopy! ay sy) (fcopy! az sz))
      (%ct-select (aref nib w))                        ; sel = nibble*G  (CT table read)
      (ct-cadd! sx sy sz  ax ay az  *ct-selx* *ct-sely* *ct-selz*)
      (fcopy! ax sx) (fcopy! ay sy) (fcopy! az sz))
    ;; projective -> affine: (X/Z, Y/Z), entirely in the FE/VOP domain so the
    ;; secret-derived coordinates never become variable-length bignums.  Z is
    ;; canonicalized first (fadd!/fsub! leave results in [0,2^256), so an infinity
    ;; result Z=p must reduce to 0 before the zero test).
    (fmul! az az *one-fe*)                            ; canonicalize Z to [0,p)
    (if (fzero? az)
        t
        (progn
          (fe-inv! *ct-zinv* az)                      ; Z^-1 via constant-time Fermat chain
          (fmul! *ct-rx* ax *ct-zinv*)                ; X/Z
          (fmul! *ct-ry* ay *ct-zinv*)                ; Y/Z
          nil))))

(defun ct-mul-g (k)
  "Constant-time K*G for 0 <= K < n.  Returns an affine (x . y) point, or the
point at infinity for K=0.  K must already be reduced (callers pass nonces /
private keys in range).  K is an integer, so it is already on the heap: secret
callers use the fixed-buffer entry points in SECRET.LISP instead."
  (if (%ct-mul-g-nib (%ct-nibbles k))
      *secp256k1-infinity*
      (cons (f->i *ct-rx*) (f->i *ct-ry*))))

(defun ct-mul-g-available-p () t)

;;; Constant-time a*b mod n via Montgomery multiplication (nmul! is the same
;;; branchless VOP path used by the verified mod-n inverse).  Used for the
;;; secret-operand multiplies in ECDSA/Schnorr signing (e*d, r*d, k^-1*...).
(defun ct-nmul (a b)
  "a*b mod n for 0 <= a,b < n, constant-time."
  (let ((o1 (mkfe)) (o2 (mkfe)))
    (nmul! o1 (i->fe a) *nR2*)        ; o1 = a*R mod n  (into Montgomery form)
    (nmul! o2 o1 (i->fe b))           ; o2 = (a*R)*b*R^-1 = a*b mod n
    (f->i o2)))

;;; ===========================================================================
;;; Constant-time VARIABLE-BASE scalar multiplication: secret K times an
;;; arbitrary point P (the ECDH case).  Same machinery as CT-MUL-G — complete
;;; projective addition for every add AND double, a fixed 4-bit window over all
;;; 64 nibbles — but the 16-entry table is built PER CALL from P (P is public;
;;; only K is secret), and the table read masks limbs instead of multiplying.
;;;
;;; What the secret controls, and what it does not:
;;;   - K is reduced mod n by %CT-SCALAR-REDUCE: one unconditional 8-word
;;;     subtract-with-borrow and a masked select (no comparison, no branch);
;;;   - the loop is 64 windows x (4 doublings + 1 select + 1 add), always;
;;;   - %CT-SELECT-TAB reads all 16 entries in order and ORs in (limb AND mask),
;;;     mask = all-ones iff i = digit — the digit never indexes memory and never
;;;     reaches a branch;
;;;   - digit 0 selects the identity (0:1:0), which the complete formula adds
;;;     correctly, so there is no zero-digit special case.
;;; Branches that DO exist are on public data only: whether P is the point at
;;; infinity (input), whether K lies outside [0, 2^256) (a range/type check —
;;; ECDH secrets are 32-byte scalars, so it never fires there), and whether the
;;; RESULT is infinity (only when K = 0 mod n for a valid P).
;;; ===========================================================================

(defconstant +ct-n-words+ 8)
(defvar *ct-n32*
  (let ((v (make-array 8 :element-type '(unsigned-byte 32)))
        (n #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141))
    (dotimes (i 8 v) (setf (aref v i) (logand n #xFFFFFFFF) n (ash n -32)))))

;; I->FE peels limbs with LOGAND/ASH, and SBCL takes a different path for a
;; FIXNUM than for a BIGNUM (and ASH's cost follows the bignum's length).  Adding
;; 2^256 first makes every intermediate in that peel a bignum of the SAME length
;; whatever K is (K+2^256 in [2^256, 2^257)), so the per-limb fixnum/bignum test
;; always goes the same way.  The discarded fifth limb is the 1 we added.
(defvar *ct-2^256* (ash 1 256))

#-modus-mul-split
(defun %ct-scalar-reduce (k)
  "K mod n for 0 <= K < 2^256, as an FE (4x64 limbs), branch-free in K.
Since 2^256 < 2n, K mod n is K or K-n: compute D = K-n over eight 32-bit words
with an arithmetic borrow, then keep K iff the final borrow is 1.  Word
arithmetic is on fixnums (|diff| < 2^33), so it never conses a bignum."
  (let* ((kf (i->fe (+ k *ct-2^256*)))   ; low 4 limbs = K; see *CT-2^256*
         (kw (make-array 8 :element-type '(unsigned-byte 32)))
         (dw (make-array 8 :element-type '(unsigned-byte 32)))
         (nw *ct-n32*) (borrow 0) (out (mkfe)))
    (declare (type fe kf out) (type (simple-array (unsigned-byte 32) (8)) kw dw nw)
             (type (integer 0 1) borrow))
    (dotimes (i 4)
      (setf (aref kw (* 2 i))      (logand (aref kf i) #xFFFFFFFF)
            (aref kw (1+ (* 2 i))) (ash (aref kf i) -32)))
    (dotimes (i 8)
      (let ((diff (- (aref kw i) (aref nw i) borrow)))
        (declare (type (signed-byte 40) diff))
        (setf (aref dw i) (logand diff #xFFFFFFFF)
              borrow (logand (ash diff -32) 1))))     ; 1 iff diff < 0
    ;; borrow = 1  <=>  K < n  ->  keep K ;  borrow = 0 -> take D = K - n.
    (let ((keep (logand (- borrow) #xFFFFFFFF)))      ; all-ones iff K < n
      (declare (type (unsigned-byte 32) keep))
      (dotimes (i 4 out)
        (let ((lo (logxor (aref dw (* 2 i))      (logand keep (logxor (aref kw (* 2 i))      (aref dw (* 2 i))))))
              (hi (logxor (aref dw (1+ (* 2 i))) (logand keep (logxor (aref kw (1+ (* 2 i))) (aref dw (1+ (* 2 i))))))))
          (declare (type (unsigned-byte 32) lo hi))
          (setf (aref out i) (logior lo (ash hi 32))))))))

#+modus-mul-split
(defun %ct-scalar-reduce (k)
  "K mod n for 0 <= K < 2^256, as an FE (5x52 limbs), branch-free in K: D = K-n
with a signed borrow rippled through the limbs, then keep K iff D < 0.  Every
intermediate is a fixnum."
  (let* ((kf (i->fe (+ k *ct-2^256*)))   ; low 256 bits = K; see *CT-2^256*
         (nf *ct-n-limbs*) (out (mkfe)) (c 0) (d (mkfe)))
    (dotimes (i 5)
      (let ((x (+ (- (svref kf i) (svref nf i)) c)))
        (if (< i 4)
            (setf c (ash x -52) (svref d i) (logand x +m52+))
            (setf (svref d i) x))))
    (let ((mask (ash (svref d 4) -62)))  ; all-ones iff K < n
      (dotimes (i 5 out)
        (setf (svref out i)
              (logxor (svref d i) (logand mask (logxor (svref kf i) (svref d i)))))))))

#+modus-mul-split
(defvar *ct-n-limbs* (i->fe #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141))

#-modus-mul-split
(defun %ct-fe-nibbles (kf)
  "The 64 base-16 digits of the 4-limb scalar KF (index = window number)."
  (declare (type fe kf))
  (let ((d (make-array 64 :element-type 'fixnum)))
    (declare (type (simple-array fixnum (64)) d))
    (dotimes (i 4 d)
      (let ((lo (logand (aref kf i) #xFFFFFFFF)) (hi (ash (aref kf i) -32)))
        (declare (type (unsigned-byte 32) lo hi))
        (dotimes (j 8)
          (setf (aref d (+ (* i 16) j))   (logand (ash lo (* -4 j)) 15)
                (aref d (+ (* i 16) 8 j)) (logand (ash hi (* -4 j)) 15)))))))

#+modus-mul-split
(defun %ct-fe-nibbles (kf)
  "The 64 base-16 digits of the 5x52-limb scalar KF (index = window number).  A
52-bit limb holds exactly 13 nibbles, so no digit straddles two limbs."
  (let ((d (make-array 64 :element-type 'fixnum)))
    (dotimes (w 64 d)
      (setf (aref d w) (logand (ash (svref kf (floor w 13)) (* -4 (mod w 13))) 15)))))

(defun %ct-point-table (p)
  "Per-call table T[i] = i*P, i = 0..15, projective, as a simple-vector of 48
FEs (entry i at 3i..3i+2).  T[0] = identity (0:1:0); T[i] = T[i-1] + P by the
complete formula.  P is public, so this costs nothing in secrecy."
  (let ((tab (make-array 48)) (px (i->fe (secp-x p))) (py (i->fe (secp-y p))) (pz (i->fe 1)))
    (setf (aref tab 0) (i->fe 0) (aref tab 1) (i->fe 1) (aref tab 2) (i->fe 0))
    (loop for i from 1 below 16 do
      (let ((ox (mkfe)) (oy (mkfe)) (oz (mkfe)) (j (* 3 (1- i))))
        (ct-cadd! ox oy oz (aref tab j) (aref tab (+ j 1)) (aref tab (+ j 2)) px py pz)
        (setf (aref tab (* 3 i)) ox (aref tab (+ (* 3 i) 1)) oy (aref tab (+ (* 3 i) 2)) oz)))
    tab))

#-modus-mul-split
(defun %ct-select-tab (tab digit sx sy sz)
  "Constant-time (sx:sy:sz) <- TAB entry DIGIT: scan all 16 entries, OR in each
limb ANDed with mask = all-ones iff i = DIGIT.  No secret-indexed access."
  (declare (type simple-vector tab) (type (integer 0 15) digit) (type fe sx sy sz)
           (optimize (speed 3) (safety 0)))
  (fill sx 0) (fill sy 0) (fill sz 0)
  (dotimes (i 16)
    (let ((m (logand (- (the (integer 0 1) (%ct-eq i digit))) #xFFFFFFFFFFFFFFFF))
          (ex (svref tab (* 3 i))) (ey (svref tab (+ (* 3 i) 1))) (ez (svref tab (+ (* 3 i) 2))))
      (declare (type (unsigned-byte 64) m) (type fe ex ey ez))
      (dotimes (l 4)
        (setf (aref sx l) (logior (aref sx l) (logand m (aref ex l)))
              (aref sy l) (logior (aref sy l) (logand m (aref ey l)))
              (aref sz l) (logior (aref sz l) (logand m (aref ez l)))))))
  nil)

#+modus-mul-split
(defun %ct-select-tab (tab digit sx sy sz)
  "Constant-time (sx:sy:sz) <- TAB entry DIGIT, as on SBCL; the mask is the fixnum
-1 (all ones over a 52-bit limb) or 0."
  (declare (type simple-vector tab) (type (simple-array t (5)) sx sy sz))
  (fill sx 0) (fill sy 0) (fill sz 0)
  (dotimes (i 16)
    (let ((m (- (%ct-eq i digit)))
          (ex (svref tab (* 3 i))) (ey (svref tab (+ (* 3 i) 1))) (ez (svref tab (+ (* 3 i) 2))))
      (declare (type (simple-array t (5)) ex ey ez))
      (dotimes (l 5)
        (setf (svref sx l) (logior (svref sx l) (logand m (svref ex l)))
              (svref sy l) (logior (svref sy l) (logand m (svref ey l)))
              (svref sz l) (logior (svref sz l) (logand m (svref ez l)))))))
  nil)

(defun %ct-mul-point-nib (nib p)
  "Constant-time digits*P for NIB (64 base-16 digits) and a public affine P on the
curve.  Returns T for the point at infinity; otherwise leaves the affine result in
*CT-RX* / *CT-RY* and returns NIL.  ECDH's result is the shared secret, so its
caller reads it out of the FEs into fixed bytes and it is never an integer."
  (declare (type (simple-array fixnum (64)) nib))
  (secp-init)
  (when (secp-inf-p p) (return-from %ct-mul-point-nib t))
  (let* ((tab (%ct-point-table p))
         (ax *ct-ax*) (ay *ct-ay*) (az *ct-az*)
         (sx *ct-sx*) (sy *ct-sy*) (sz *ct-sz*)
         (qx *ct-selx*) (qy *ct-sely*) (qz *ct-selz*))
    (i->fe! ax 0) (i->fe! ay 1) (i->fe! az 0)          ; accumulator = identity
    (loop for w fixnum from 63 downto 0 do
      (dotimes (i 4)                                     ; acc <- 16*acc
        (ct-cadd! sx sy sz  ax ay az  ax ay az)
        (fcopy! ax sx) (fcopy! ay sy) (fcopy! az sz))
      (%ct-select-tab tab (aref nib w) qx qy qz)         ; q = digit*P (CT read)
      (ct-cadd! sx sy sz  ax ay az  qx qy qz)
      (fcopy! ax sx) (fcopy! ay sy) (fcopy! az sz))
    ;; projective -> affine exactly as CT-MUL-G does it.
    (fmul! az az *one-fe*)
    (if (fzero? az)
        t
        (progn
          (fe-inv! *ct-zinv* az)
          (fmul! *ct-rx* ax *ct-zinv*)
          (fmul! *ct-ry* ay *ct-zinv*)
          nil))))

(defun ct-mul-point (k p)
  "Constant-time K*P for a scalar K and any (public) affine point P.  Same result
as SECP-MUL-POINT for every integer K: K is reduced mod n.  K in [0, 2^256) takes the
branch-free path; anything else is first reduced with a variable-time MOD (a range
check on the input's type, not its value).  K is an integer, already on the heap:
secret callers use ECDH-X in SECRET.LISP, which never makes the scalar or the result
an integer."
  (secp-init)
  (when (secp-inf-p p) (return-from ct-mul-point *secp256k1-infinity*))
  (let ((k (if (and (integerp k) (<= 0 k) (< k (ash 1 256))) k (mod k *secp256k1-n*))))
    (if (%ct-mul-point-nib (%ct-fe-nibbles (%ct-scalar-reduce k)) p)
        *secp256k1-infinity*
        (cons (f->i *ct-rx*) (f->i *ct-ry*)))))

(defun ct-mul-point-available-p () t)

;;; ---------------------------------------------------------------------------
;;; Thread safety
;;;
;;; The scratch above is module-level, which is the right call for the
;;; single-threaded fast path and wrong the moment two threads derive keys or
;;; sign at the same time: they overwrite each other's intermediates and the
;;; result comes back as the point at infinity, or — worse — a valid-looking
;;; wrong point.  CT-MUL-G is reached from SECP-PUBKEY, ECDSA-SIGN-RAW and
;;; SCHNORR-SIGN, so this covers key derivation and both signature schemes.
;;;
;;; FIELD-LIMB.LISP's WITH-FRESH-SCRATCH deliberately does NOT cover these: it
;;; was written for parallel *verification*, which goes through SECP-MUL-POINT
;;; and touches a disjoint set of buffers.  A caller doing concurrent signing
;;; needs this one as well — WITH-FRESH-SCRATCH alone silently does nothing for
;;; CT-MUL-G, which is a confusing way to find out.
;;;
;;; *CT-GTAB* and *CT-B3* are NOT rebound: the table is read-only once built, so
;;; sharing it is both safe and the point (rebinding would rebuild 16 point
;;; multiplications per thread).  It is built eagerly below so threads never race
;;; to construct it.
;;; ---------------------------------------------------------------------------

(defmacro with-fresh-ct-scratch (&body body)
  "Bind CT-MUL-G's scratch for this thread.  Wrap any thread that derives public
   keys or signs; without it, concurrent callers corrupt each other.

   This ALSO binds the field-arithmetic scratch (WITH-FRESH-SCRATCH), because
   CT-CADD! bottoms out in FMUL!/FADD! and those have their own module-level
   buffers.  Binding only one of the two leaves the other shared, which fails
   exactly as loudly as binding neither — so this macro is deliberately
   sufficient on its own rather than something callers must remember to pair."
  `(with-fresh-scratch
     (%with-ct-buffers-only ,@body)))

(defmacro %with-ct-buffers-only (&body body)
  "Inside WITH-SECRET-SCRATCH the buffers are already bound to fixed memory, and
rebinding them to fresh heap arrays would put secret intermediates back on the
moving heap -- so in a secret scope this binds nothing."
  (let ((f (gensym "BODY")))
    `(flet ((,f () ,@body))
       (if *secret-scope* (,f) (%with-ct-buffers-fresh (,f))))))

(defmacro %with-ct-buffers-fresh (&body body)
  `(let ((*ct-t0* (mkfe)) (*ct-t1* (mkfe)) (*ct-t2* (mkfe))
         (*ct-t3* (mkfe)) (*ct-t4* (mkfe))
         (*ct-selx* (mkfe)) (*ct-sely* (mkfe)) (*ct-selz* (mkfe))
         (*ct-ax* (mkfe)) (*ct-ay* (mkfe)) (*ct-az* (mkfe))
         (*ct-sx* (mkfe)) (*ct-sy* (mkfe)) (*ct-sz* (mkfe))
         (*ct-zinv* (mkfe)) (*ct-rx* (mkfe)) (*ct-ry* (mkfe)))
     ,@body))

;; Build the generator table at load time, so a first concurrent call can't have
;; two threads constructing it at once.
(secp-init)
(%ct-table)
(%ct-gtab-flat)
