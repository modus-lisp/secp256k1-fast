;;;; fe-sbcl.lisp — the limb field layer on SBCL: 4x64-bit limbs over the VOPs.
;;;;
;;;; Loaded on SBCL (x86-64, arm64) after the per-architecture VOP file and
;;;; before field-limb.lisp.  It supplies the interface the point layer in
;;;; field-limb.lisp and the constant-time code in ct.lisp are written against:
;;;; FE, MKFE, FMUL! FSQR! FADD! FSUB! FDBL! FCOPY! FZERO? I->FE I->FE! F->I, the
;;;; Montgomery product mod n NMUL!/NSQR! with *NR* *NR2*, and the 128-bit scalar
;;;; recoders NAF-INTO / WNAF-INTO.  fe-modus.lisp is the same interface on
;;;; modus's 5x52-bit fixnum limbs.  (Moved here verbatim from field-limb.lisp.)

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
;; Limbs are peeled with a CONSTANT mask and a CONSTANT shift, never with
;; (ldb (byte 64 (* i 64)) x).  SBCL 2.6.8 (x86-64) open-codes a variable-position
;; LDB on an integer as a two-digit SHRD whose shift-count TN can be packed into
;; the same register as the digit it loads (MOV RDI,RAX clobbers the count, then
;; MOV ECX,EDI) -- so under register pressure (e.g. i->fe inlined next to FADD!)
;; every limb came out shifted by garbage.  SBCL 2.2.9 called ASH and was correct.
(defun i->fe (x) (let ((a (mkfe))) (dotimes (i 4 a) (setf (aref a i) (logand x #xFFFFFFFFFFFFFFFF) x (ash x -64)))))
(declaim (inline i->fe!))
(defun i->fe! (out x) (declare (type fe out)) (dotimes (i 4 out) (setf (aref out i) (logand x #xFFFFFFFFFFFFFFFF) x (ash x -64))))
(defun f->i (a) (declare (type fe a)) (logior (aref a 0) (ash (aref a 1) 64) (ash (aref a 2) 128) (ash (aref a 3) 192)))

;;; Montgomery product mod n (R = 2^256); N-INV! in field-limb.lisp uses it.
(defvar *mont-scratch* (make-array 9 :element-type '(unsigned-byte 64) :initial-element 0))
(defvar *nR*    (i->fe #x14551231950B75FC4402DA1732FC9BEBF))                                 ; R   mod n = mont(1)
(defvar *nR2*   (i->fe #x9D671CD581C69BC5E697F5E45BCD07C6741496C20E7CF878896CF21467D7D140))   ; R^2 mod n

(declaim (inline nmul! nsqr!))
(defun nmul! (out a b)
  "out = a*b*R^-1 mod n (Montgomery product)."
  (declare (type fe out a b) (optimize (speed 3) (safety 0)))
  (sb-sys:with-pinned-objects (a b out *mont-scratch*)
    (%mul256 (sb-sys:vector-sap a) (sb-sys:vector-sap b) (sb-sys:vector-sap *mont-scratch*))
    (%montredn (sb-sys:vector-sap *mont-scratch*) (sb-sys:vector-sap out))))
(defun nsqr! (out a) (nmul! out a a))

;; NAF/wNAF recoding over a 2-limb (lo,hi) view of the sub-scalar (< 2^128).
;; Looping on the bignum K (ash/decf) conses ~128 bignums per call — the second
;; biggest verify allocator after the mod-n inverse — so shift/subtract the
;; scalar as two (unsigned-byte 64) limbs, kept unboxed via #xFFFF...-masking.
(defmacro %m64 (x) `(logand ,x #xFFFFFFFFFFFFFFFF))
(declaim (inline naf-into wnaf-into))
(defun naf-into (k buf)
  "NAF of K (< 2^128) into BUF → length.  Allocation-free (limb recoding)."
  (declare (type (simple-array fixnum (*)) buf) (optimize (speed 3) (safety 0)))
  (let ((lo (ldb (byte 64 0) k)) (hi (ldb (byte 64 64) k)) (i 0))
    (declare (type (unsigned-byte 64) lo hi) (type fixnum i))
    (loop until (and (zerop lo) (zerop hi)) do
      (cond ((logbitp 0 lo)
             (let ((z (- 2 (logand lo 3))))                 ; lo odd → z in {1,-1}
               (setf (aref buf i) z)
               (if (= z 1)
                   (setf lo (%m64 (- lo 1)))                ; lo odd → no borrow
                   (if (= lo #xFFFFFFFFFFFFFFFF)
                       (setf lo 0 hi (%m64 (+ hi 1)))
                       (setf lo (%m64 (+ lo 1)))))))
            (t (setf (aref buf i) 0)))
      (setf lo (%m64 (logior (ash lo -1) (ash (logand hi 1) 63))) hi (ash hi -1))
      (incf i))
    i))

(defun wnaf-into (k w buf)
  "Width-w NAF of K (< 2^128) into BUF → length.  Allocation-free (limb recoding)."
  (declare (type (simple-array fixnum (*)) buf) (type (integer 1 16) w) (optimize (speed 3) (safety 0)))
  (let ((lo (ldb (byte 64 0) k)) (hi (ldb (byte 64 64) k)) (i 0)
        (m (ash 1 w)) (mh (ash 1 (1- w))))
    (declare (type (unsigned-byte 64) lo hi) (type fixnum i m mh))
    (loop until (and (zerop lo) (zerop hi)) do
      (cond ((logbitp 0 lo)
             (let ((z (logand lo (- m 1))))                 ; lo mod 2^w (w<=16 → fixnum)
               (when (>= z mh) (decf z m))                  ; signed digit, |z| < 2^(w-1)
               (setf (aref buf i) z)
               (if (>= z 0)
                   (setf lo (%m64 (- lo z)))                ; z>0 → z<=lo, no borrow
                   (let ((zz (- z)))
                     (if (<= lo (- #xFFFFFFFFFFFFFFFF zz))
                         (setf lo (%m64 (+ lo zz)))
                         (setf lo (%m64 (+ lo zz)) hi (%m64 (+ hi 1))))))))
            (t (setf (aref buf i) 0)))
      (setf lo (%m64 (logior (ash lo -1) (ash (logand hi 1) 63))) hi (ash hi -1))
      (incf i))
    i))
