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
;;;;   - a constant-time table read: every window scans all 16 entries and selects
;;;;     with field-arithmetic masking (multiply by a 0/1 flag), so the secret
;;;;     nibble never indexes memory.
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
(defvar *ct-tmp* (mkfe)) (defvar *ct-self* (mkfe))

(defun %ct-select (digit)
  "Constant-time read of table entry DIGIT into (*ct-selx* *ct-sely* *ct-selz*):
scan all 16, accumulate entry*flag where flag = (i==digit)."
  (declare (type fixnum digit) (optimize (speed 3) (safety 0)))
  (let ((tab (%ct-table)) (sx *ct-selx*) (sy *ct-sely*) (sz *ct-selz*)
        (tmp *ct-tmp*) (self *ct-self*))
    (fill sx 0) (fill sy 0) (fill sz 0)
    (dotimes (i 16)
      (i->fe! self (%ct-eq i digit))         ; 0 or 1 as a field element
      (let ((e (aref tab i)))
        (fmul! tmp self (aref e 0)) (fadd! sx sx tmp)
        (fmul! tmp self (aref e 1)) (fadd! sy sy tmp)
        (fmul! tmp self (aref e 2)) (fadd! sz sz tmp)))))

(defvar *ct-ax* (mkfe)) (defvar *ct-ay* (mkfe)) (defvar *ct-az* (mkfe))
(defvar *ct-sx* (mkfe)) (defvar *ct-sy* (mkfe)) (defvar *ct-sz* (mkfe))
(defvar *ct-zinv* (mkfe)) (defvar *ct-rx* (mkfe)) (defvar *ct-ry* (mkfe))

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

(defun ct-mul-g (k)
  "Constant-time K*G for 0 <= K < n.  Returns an affine (x . y) point, or the
point at infinity for K=0.  K must already be reduced (callers pass nonces /
private keys in range)."
  (secp-init)
  (let ((ax *ct-ax*) (ay *ct-ay*) (az *ct-az*)
        (sx *ct-sx*) (sy *ct-sy*) (sz *ct-sz*)
        (nib (%ct-nibbles k)))
    (declare (type (simple-array fixnum (64)) nib))
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
    ;; result Z=p must reduce to 0 before the zero test).  f->i runs only on the
    ;; final affine x,y — which are the public output point.
    (fmul! az az *one-fe*)                            ; canonicalize Z to [0,p)
    (if (fzero? az)
        *secp256k1-infinity*
        (progn
          (fe-inv! *ct-zinv* az)                      ; Z^-1 via constant-time Fermat chain
          (fmul! *ct-rx* ax *ct-zinv*)                ; X/Z
          (fmul! *ct-ry* ay *ct-zinv*)                ; Y/Z
          (cons (f->i *ct-rx*) (f->i *ct-ry*))))))

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
