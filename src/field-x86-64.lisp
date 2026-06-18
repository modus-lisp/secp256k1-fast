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

;;; ===========================================================================
;;; Limb Jacobian point arithmetic (X Y Z each an FE; infinity = Z all-zero)
;;; ===========================================================================
;;; Scratch FEs are module-level (single-threaded fast path; see header note).

(defvar *tA* (mkfe)) (defvar *tB* (mkfe)) (defvar *tC* (mkfe)) (defvar *tD* (mkfe))
(defvar *tE* (mkfe)) (defvar *tF* (mkfe)) (defvar *tG* (mkfe))
(defvar *one-fe* (i->fe 1))

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
;;; Redefine the public scalar-mult entry points to use the limb backend.
;;; (ECDSA / Schnorr call these at runtime, so the redefinition takes effect.)
;;; ===========================================================================

(defun secp-mul-point (k p)
  (secp-init)
  (if (secp-inf-p p)
      *secp256k1-infinity*
      (let ((kk (mod k *secp256k1-n*)))
        (if (zerop kk)
            *secp256k1-infinity*
            (multiple-value-bind (x y) (limb-mul-point kk (secp-x p) (secp-y p))
              (if (eq x :inf) *secp256k1-infinity* (cons x y)))))))

(defun secp-mul-2 (k1 p1 k2 p2)
  (secp-init)
  (if (or (secp-inf-p p1) (secp-inf-p p2))
      (secp-add-points (secp-mul-point k1 p1) (secp-mul-point k2 p2))
      (multiple-value-bind (x y)
          (limb-mul-2 (mod k1 *secp256k1-n*) (secp-x p1) (secp-y p1)
                      (mod k2 *secp256k1-n*) (secp-x p2) (secp-y p2))
        (if (eq x :inf) *secp256k1-infinity* (cons x y)))))
