;;;; field-x86-64.lisp — x86-64 limb field + point backend.
;;;;
;;;; Loaded ONLY on SBCL/x86-64 and LAST.  Uses the field VOPs from
;;;; field-vops-x86-64.lisp (loaded just before this) to run the scalar-
;;;; multiplication hot path entirely on 4x64-bit limb arrays with no per-op
;;;; allocation, then REDEFINES SECP-MUL-POINT / SECP-MUL-2 so ECDSA/Schnorr
;;;; verify go through it.  Portable field.lisp / point.lisp stay as the fallback
;;;; AND the differential oracle (cross-checked byte-for-byte vs cl-consensus,
;;;; which is checked vs Bitcoin Core).
;;;;
;;;; NOTE: the scalar-mult scratch buffers are module-level → the fast path is
;;;; currently single-threaded (fine for tests + a single IBD thread).  Per-call
;;;; / thread-local buffers are a follow-up for parallel IBD.

(in-package #:secp256k1-fast)

;;; ===========================================================================
;;; Limb field-element wrappers (4x (unsigned-byte 64))
;;; ===========================================================================

(deftype fe () '(simple-array (unsigned-byte 64) (4)))
(declaim (inline mkfe fmul! fsqr! fadd! fsub! fdbl! fcopy! fzero? i->fe f->i))
(defun mkfe () (make-array 4 :element-type '(unsigned-byte 64) :initial-element 0))
(defvar *fmul-scratch* (make-array 8 :element-type '(unsigned-byte 64)))

(defun fmul! (out a b)
  (declare (type fe out a b) (optimize (speed 3) (safety 0)))
  (sb-sys:with-pinned-objects (a b out *fmul-scratch*)
    (%mul256 (sb-sys:vector-sap a) (sb-sys:vector-sap b) (sb-sys:vector-sap *fmul-scratch*))
    (%reducep (sb-sys:vector-sap *fmul-scratch*) (sb-sys:vector-sap out))))
(defun fsqr! (out a) (fmul! out a a))
(defun fadd! (out a b)
  (declare (type fe out a b) (optimize (speed 3) (safety 0)))
  (sb-sys:with-pinned-objects (a b out) (%fadd (sb-sys:vector-sap a) (sb-sys:vector-sap b) (sb-sys:vector-sap out))))
(defun fsub! (out a b)
  (declare (type fe out a b) (optimize (speed 3) (safety 0)))
  (sb-sys:with-pinned-objects (a b out) (%fsub (sb-sys:vector-sap a) (sb-sys:vector-sap b) (sb-sys:vector-sap out))))
(defun fdbl! (out a) (fadd! out a a))
(defun fcopy! (out a) (declare (type fe out a)) (dotimes (i 4) (setf (aref out i) (aref a i))))
(defun fzero? (a) (declare (type fe a)) (and (zerop (aref a 0)) (zerop (aref a 1)) (zerop (aref a 2)) (zerop (aref a 3))))
(defun i->fe (x) (let ((a (mkfe))) (dotimes (i 4 a) (setf (aref a i) (ldb (byte 64 (* i 64)) x)))))
(defun f->i (a) (declare (type fe a)) (logior (aref a 0) (ash (aref a 1) 64) (ash (aref a 2) 128) (ash (aref a 3) 192)))

;;; Field inverse via Fermat (a^(p-2) mod p) on the VOP field — replaces the
;;; extended-Euclid SECP-INV (which was ~33% of verify in bignum arithmetic).
;;; The VOP square-and-multiply costs ~256 fsqr! + ~256 fmul! ~ 11us vs ~25us.
(defvar *one-fe* (i->fe 1))
(defvar *inv-r* (mkfe)) (defvar *inv-a* (mkfe))
(defvar *p-minus-2* nil)
(defun fast-inv (a)
  "Integer modular inverse mod p via Fermat on the limb VOP field."
  (secp-init)
  (let ((am (mod a *secp256k1-p*)))
    (if (zerop am)
        0
        (progn
          (unless *p-minus-2* (setf *p-minus-2* (- *secp256k1-p* 2)))
          (fcopy! *inv-a* (i->fe am))
          (fcopy! *inv-r* *one-fe*)
          (loop for i fixnum from 255 downto 0 do
            (fsqr! *inv-r* *inv-r*)
            (when (logbitp i *p-minus-2*) (fmul! *inv-r* *inv-r* *inv-a*)))
          (f->i *inv-r*)))))
;; redefine the public SECP-INV (mod p) to use it — speeds jac->affine + the
;; Shamir precompute's affine point-add, and the reference point.lisp helpers.
(defun secp-inv (a) (fast-inv a))

;;; ===========================================================================
;;; Limb Jacobian point arithmetic (X Y Z each an FE; infinity = Z all-zero)
;;; ===========================================================================
;;; Scratch FEs are module-level (single-threaded fast path; see header note).

(defvar *tA* (mkfe)) (defvar *tB* (mkfe)) (defvar *tC* (mkfe)) (defvar *tD* (mkfe))
(defvar *tE* (mkfe)) (defvar *tF* (mkfe)) (defvar *tG* (mkfe))

(defun jdbl! (x y z)                            ; in-place double of (x y z)
  (declare (type fe x y z) (optimize (speed 3) (safety 0)))
  (when (fzero? z) (return-from jdbl!))
  (fmul! *tG* y z) (fdbl! *tG* *tG*)            ; Z3 = 2YZ (save first; clobber Y later)
  (fsqr! *tA* x) (fsqr! *tB* y) (fsqr! *tC* *tB*)
  (fadd! *tD* x *tB*) (fsqr! *tD* *tD*) (fsub! *tD* *tD* *tA*) (fsub! *tD* *tD* *tC*) (fdbl! *tD* *tD*) ; D
  (fadd! *tE* *tA* *tA*) (fadd! *tE* *tE* *tA*) ; E = 3A
  (fsqr! *tF* *tE*)                             ; F
  (fdbl! x *tD*) (fsub! x *tF* x)               ; X3 = F - 2D
  (fdbl! *tB* *tC*) (fdbl! *tB* *tB*) (fdbl! *tB* *tB*)  ; 8C
  (fsub! *tA* *tD* x) (fmul! *tA* *tE* *tA*) (fsub! y *tA* *tB*)  ; Y3 = E(D-X3) - 8C
  (fcopy! z *tG*))

(defvar *aZZ* (mkfe)) (defvar *aU2* (mkfe)) (defvar *aS2* (mkfe)) (defvar *aH* (mkfe))
(defvar *aRR* (mkfe)) (defvar *aHH* (mkfe)) (defvar *aI* (mkfe)) (defvar *aJ* (mkfe))
(defvar *aV* (mkfe)) (defvar *aT* (mkfe))

(defun jadd! (x y z ax ay)                      ; in-place (x y z) += affine (ax ay)
  (declare (type fe x y z ax ay) (optimize (speed 3) (safety 0)))
  (cond
    ((fzero? z) (fcopy! x ax) (fcopy! y ay) (fcopy! z *one-fe*))
    (t (fsqr! *aZZ* z) (fmul! *aU2* ax *aZZ*) (fmul! *aS2* z *aZZ*) (fmul! *aS2* ay *aS2*)
       (fsub! *aH* *aU2* x) (fsub! *aRR* *aS2* y)
       (cond
         ((fzero? *aH*) (if (fzero? *aRR*) (jdbl! x y z) (fill z 0)))   ; same point→double; opposite→∞
         (t (fsqr! *aHH* *aH*) (fdbl! *aI* *aHH*) (fdbl! *aI* *aI*)     ; I = 4HH
            (fmul! *aJ* *aH* *aI*) (fdbl! *aRR* *aRR*) (fmul! *aV* x *aI*)
            (fsqr! *aT* *aRR*) (fsub! *aT* *aT* *aJ*) (fdbl! x *aV*) (fsub! x *aT* x)  ; X3
            (fsub! *aT* *aV* x) (fmul! *aT* *aRR* *aT*) (fmul! *aV* y *aJ*) (fdbl! *aV* *aV*) (fsub! y *aT* *aV*)  ; Y3
            (fadd! *aT* z *aH*) (fsqr! *aT* *aT*) (fsub! *aT* *aT* *aZZ*) (fsub! z *aT* *aHH*))))))  ; Z3

(defun jac->affine-int (x y z)
  "Jacobian limb point → affine integer point, or :inf.  One field inverse."
  (if (fzero? z) (values :inf :inf)
      (let* ((zi (secp-inv (f->i z))) (zi2 (secp-mod (* zi zi))))
        (values (secp-mod (* (f->i x) zi2)) (secp-mod (* (f->i y) zi2 zi))))))

(defvar *RX* (mkfe)) (defvar *RY* (mkfe)) (defvar *RZ* (mkfe))
(defvar *b1x* (mkfe)) (defvar *b1y* (mkfe)) (defvar *b2x* (mkfe)) (defvar *b2y* (mkfe))
(defvar *sumx* (mkfe)) (defvar *sumy* (mkfe))

(defun limb-mul-point (k px py)
  "k * affine-int (px,py) → affine integer point (or :inf)."
  (declare (optimize (speed 3) (safety 0)))
  (fcopy! *b1x* (i->fe px)) (fcopy! *b1y* (i->fe py))
  (fill *RX* 0) (fill *RY* 0) (fill *RZ* 0)
  (loop for i fixnum from (1- (integer-length k)) downto 0 do
    (jdbl! *RX* *RY* *RZ*)
    (when (logbitp i k) (jadd! *RX* *RY* *RZ* *b1x* *b1y*)))
  (jac->affine-int *RX* *RY* *RZ*))

(defun limb-mul-2 (k1 x1 y1 k2 x2 y2)
  "k1*(x1,y1) + k2*(x2,y2) via Shamir's trick on the limb backend → affine int / :inf."
  (declare (optimize (speed 3) (safety 0)))
  (fcopy! *b1x* (i->fe x1)) (fcopy! *b1y* (i->fe y1))
  (fcopy! *b2x* (i->fe x2)) (fcopy! *b2y* (i->fe y2))
  (let* ((sum (secp-add-points (cons x1 y1) (cons x2 y2)))   ; precompute b1+b2 (affine int)
         (sum-inf (secp-inf-p sum)))
    (unless sum-inf (fcopy! *sumx* (i->fe (secp-x sum))) (fcopy! *sumy* (i->fe (secp-y sum))))
    (fill *RX* 0) (fill *RY* 0) (fill *RZ* 0)
    (loop for i fixnum from (1- (max (integer-length k1) (integer-length k2))) downto 0 do
      (jdbl! *RX* *RY* *RZ*)
      (let ((b1 (logbitp i k1)) (b2 (logbitp i k2)))
        (cond ((and b1 b2) (unless sum-inf (jadd! *RX* *RY* *RZ* *sumx* *sumy*)))
              (b1 (jadd! *RX* *RY* *RZ* *b1x* *b1y*))
              (b2 (jadd! *RX* *RY* *RZ* *b2x* *b2y*)))))
    (jac->affine-int *RX* *RY* *RZ*)))

;;; ===========================================================================
;;; GLV endomorphism + NAF.  secp256k1 has phi(x,y) = (beta*x, y) = lambda*P, so
;;; k*P = k1*P + k2*(lambda*P) with k1,k2 ~128-bit (signed) — HALVING the
;;; doublings.  NAF (density 1/3) keeps the extra additions in check without
;;; precomputed tables.  Constants lifted from libsecp256k1 scalar_impl.h /
;;; field.h; the whole thing is verified against the differential cross-check.
;;; ===========================================================================

(defconstant +glv-lambda+ #x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72)
(defconstant +glv-g1+     #x3086D221A7D46BCDE86C90E49284EB153DAA8A1471E8CA7FE893209A45DBB031)
(defconstant +glv-g2+     #xE4437ED6010E88286F547FA90ABFE4C4221208AC9DF506C61571B4AE8AC47F71)
(defconstant +glv-mb1+    #xE4437ED6010E88286F547FA90ABFE4C3)
(defconstant +glv-mb2+    #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE8A280AC50774346DD765CDA83DB1562C)
(defvar *glv-beta* nil)
(defun glv-beta () (or *glv-beta*
  (setf *glv-beta* (i->fe #x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee))))

(defun glv-split (k)
  "Split k (mod n) into (values m1 neg1 m2 neg2): k = (+/-)m1 + (+/-)m2*lambda
   (mod n), with m1, m2 < 2^128 (magnitudes; neg flags carry the sign)."
  (let* ((n *secp256k1-n*)
         (c1 (let ((l (* k +glv-g1+))) (+ (ash l -384) (logand (ash l -383) 1))))
         (c2 (let ((l (* k +glv-g2+))) (+ (ash l -384) (logand (ash l -383) 1))))
         (r2 (mod (+ (* c1 +glv-mb1+) (* c2 +glv-mb2+)) n))
         (r1 (mod (- k (mod (* r2 +glv-lambda+) n)) n))
         (m1 r1) (neg1 nil) (m2 r2) (neg2 nil) (h (ash n -1)))
    (when (> r1 h) (setf m1 (- n r1) neg1 t))
    (when (> r2 h) (setf m2 (- n r2) neg2 t))
    (values m1 neg1 m2 neg2)))

(defun naf (k)
  "Non-adjacent form of K → (values digit-vector length), digits in {-1,0,1},
   index 0 = bit 0.  ~1/3 of digits nonzero."
  (let ((d (make-array (+ 2 (integer-length k)) :element-type 'fixnum :initial-element 0)) (i 0) (kk k))
    (loop while (plusp kk) do
      (if (oddp kk) (let ((z (- 2 (mod kk 4)))) (setf (aref d i) z) (decf kk z)) (setf (aref d i) 0))
      (setf kk (ash kk -1)) (incf i))
    (values d i)))

(defun negy-int (y) (if (zerop y) 0 (- *secp256k1-p* y)))

;;; reusable buffers (single-threaded fast path)
(defvar *gx* (mkfe)) (defvar *gy* (mkfe)) (defvar *gz* (mkfe))

(defmacro %addbit (x yplus yminus dvec i)
  `(let ((e (aref ,dvec ,i)))
     (cond ((= e 1) (jadd! *gx* *gy* *gz* ,x ,yplus)) ((= e -1) (jadd! *gx* *gy* *gz* ,x ,yminus)))))

(defun glv-mul-point (k px py)
  "k * affine-int (px,py) via GLV + NAF → affine int / :inf."
  (declare (optimize (speed 3) (safety 0)))
  (multiple-value-bind (m1 n1 m2 n2) (glv-split k)
    (let* ((xf (i->fe px)) (lxf (mkfe)) (yf (i->fe py)) (nyf (i->fe (negy-int py))))
      (fmul! lxf (glv-beta) xf)                    ; lambda*P x = beta*px
      (let ((y1+ (if n1 nyf yf)) (y1- (if n1 yf nyf))
            (y2+ (if n2 nyf yf)) (y2- (if n2 yf nyf)))
        (multiple-value-bind (d1 l1) (naf m1)
          (multiple-value-bind (d2 l2) (naf m2)
            (fill *gx* 0) (fill *gy* 0) (fill *gz* 0)
            (loop for i fixnum from (1- (max l1 l2)) downto 0 do
              (jdbl! *gx* *gy* *gz*)
              (when (< i l1) (%addbit xf y1+ y1- d1 i))
              (when (< i l2) (%addbit lxf y2+ y2- d2 i)))
            (jac->affine-int *gx* *gy* *gz*)))))))

(defun glv-mul-2 (k1 px1 py1 k2 px2 py2)
  "k1*(px1,py1) + k2*(px2,py2) via GLV + NAF (4 sub-scalars, ~128 doublings)."
  (declare (optimize (speed 3) (safety 0)))
  (multiple-value-bind (ma na mb nb) (glv-split k1)
    (multiple-value-bind (mc nc md nd) (glv-split k2)
      (let* ((x1 (i->fe px1)) (lx1 (mkfe)) (y1 (i->fe py1)) (ny1 (i->fe (negy-int py1)))
             (x2 (i->fe px2)) (lx2 (mkfe)) (y2 (i->fe py2)) (ny2 (i->fe (negy-int py2))))
        (fmul! lx1 (glv-beta) x1) (fmul! lx2 (glv-beta) x2)
        (let ((ya+ (if na ny1 y1)) (ya- (if na y1 ny1)) (yb+ (if nb ny1 y1)) (yb- (if nb y1 ny1))
              (yc+ (if nc ny2 y2)) (yc- (if nc y2 ny2)) (yd+ (if nd ny2 y2)) (yd- (if nd y2 ny2)))
          (multiple-value-bind (da la) (naf ma) (multiple-value-bind (db lb) (naf mb)
          (multiple-value-bind (dc lc) (naf mc) (multiple-value-bind (dd ld) (naf md)
            (fill *gx* 0) (fill *gy* 0) (fill *gz* 0)
            (loop for i fixnum from (1- (max la lb lc ld)) downto 0 do
              (jdbl! *gx* *gy* *gz*)
              (when (< i la) (%addbit x1 ya+ ya- da i))
              (when (< i lb) (%addbit lx1 yb+ yb- db i))
              (when (< i lc) (%addbit x2 yc+ yc- dc i))
              (when (< i ld) (%addbit lx2 yd+ yd- dd i)))
            (jac->affine-int *gx* *gy* *gz*))))))))))

;;; re-point the public entry functions to the GLV implementations (last def wins)
(defun secp-mul-point (k p)
  (secp-init)
  (if (secp-inf-p p)
      *secp256k1-infinity*
      (let ((kk (mod k *secp256k1-n*)))
        (if (zerop kk)
            *secp256k1-infinity*
            (multiple-value-bind (x y) (glv-mul-point kk (secp-x p) (secp-y p))
              (if (eq x :inf) *secp256k1-infinity* (cons x y)))))))

(defun secp-mul-2 (k1 p1 k2 p2)
  (secp-init)
  (if (or (secp-inf-p p1) (secp-inf-p p2))
      (secp-add-points (secp-mul-point k1 p1) (secp-mul-point k2 p2))
      (multiple-value-bind (x y)
          (glv-mul-2 (mod k1 *secp256k1-n*) (secp-x p1) (secp-y p1)
                     (mod k2 *secp256k1-n*) (secp-x p2) (secp-y p2))
        (if (eq x :inf) *secp256k1-infinity* (cons x y)))))
