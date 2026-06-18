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
;;;; The scalar-mult scratch buffers are module-level (fast, zero per-op alloc).
;;;; For parallel verify, WITH-FRESH-SCRATCH (bottom of file) rebinds them
;;;; per-thread — wrap each worker thread's verify loop in it.

(in-package #:secp256k1-fast)

;; This file intentionally overrides SECP-INV / SECP-MUL-POINT / SECP-MUL-2 from
;; the portable field.lisp / point.lisp with the fast x86-64 backend — muffle the
;; expected redefinition warnings (the portable versions remain the fallback on
;; other architectures and the differential oracle).
(declaim (sb-ext:muffle-conditions sb-kernel:redefinition-warning))

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
(declaim (inline i->fe!))
(defun i->fe! (out x) (declare (type fe out)) (dotimes (i 4 out) (setf (aref out i) (ldb (byte 64 (* i 64)) x))))
(defun f->i (a) (declare (type fe a)) (logior (aref a 0) (ash (aref a 1) 64) (ash (aref a 2) 128) (ash (aref a 3) 192)))

;;; Field inverse a^(p-2) mod p via libsecp256k1's addition chain (~255 squarings
;;; + 14 multiplies), on the VOP field — ~6us vs ~11us for naive Fermat (which
;;; multiplied on every set bit of p-2).  Also used to batch-normalize the wNAF
;;; tables, so a faster inverse compounds there.
(defvar *one-fe* (i->fe 1))
(defvar *inv-r* (mkfe))
(defvar *ivx2* (mkfe)) (defvar *ivx3* (mkfe)) (defvar *ivx6* (mkfe)) (defvar *ivx9* (mkfe))
(defvar *ivx11* (mkfe)) (defvar *ivx22* (mkfe)) (defvar *ivx44* (mkfe)) (defvar *ivx88* (mkfe))
(defvar *ivx176* (mkfe)) (defvar *ivx220* (mkfe)) (defvar *ivx223* (mkfe))
(declaim (inline fsqr-n))
(defun fsqr-n (out a n)
  "out = a^(2^n) — square A N times (N >= 1)."
  (declare (type fe out a) (type fixnum n) (optimize (speed 3) (safety 0)))
  (fsqr! out a) (dotimes (i (1- n)) (fsqr! out out)))

(defun fe-inv! (out a)
  "out = a^(p-2) mod p, fe (assumes a /= 0).  libsecp's addition chain."
  (declare (type fe out a) (optimize (speed 3) (safety 0)))
  (fsqr! *ivx2* a)       (fmul! *ivx2* *ivx2* a)         ; x2  = a^(2^2-1)
  (fsqr! *ivx3* *ivx2*)  (fmul! *ivx3* *ivx3* a)         ; x3  = a^(2^3-1)
  (fsqr-n *ivx6* *ivx3* 3)    (fmul! *ivx6* *ivx6* *ivx3*)    ; x6
  (fsqr-n *ivx9* *ivx6* 3)    (fmul! *ivx9* *ivx9* *ivx3*)    ; x9
  (fsqr-n *ivx11* *ivx9* 2)   (fmul! *ivx11* *ivx11* *ivx2*)  ; x11
  (fsqr-n *ivx22* *ivx11* 11) (fmul! *ivx22* *ivx22* *ivx11*) ; x22
  (fsqr-n *ivx44* *ivx22* 22) (fmul! *ivx44* *ivx44* *ivx22*) ; x44
  (fsqr-n *ivx88* *ivx44* 44) (fmul! *ivx88* *ivx88* *ivx44*) ; x88
  (fsqr-n *ivx176* *ivx88* 88) (fmul! *ivx176* *ivx176* *ivx88*) ; x176
  (fsqr-n *ivx220* *ivx176* 44) (fmul! *ivx220* *ivx220* *ivx44*) ; x220
  (fsqr-n *ivx223* *ivx220* 3) (fmul! *ivx223* *ivx223* *ivx3*)   ; x223
  (fsqr-n out *ivx223* 23) (fmul! out out *ivx22*)
  (fsqr-n out out 5)       (fmul! out out a)
  (fsqr-n out out 3)       (fmul! out out *ivx2*)
  (fsqr-n out out 2)       (fmul! out out a))

(defun fast-inv (a)
  "Integer modular inverse mod p (addition chain on the VOP field)."
  (secp-init)
  (let ((am (mod a *secp256k1-p*)))
    (if (zerop am) 0 (progn (fe-inv! *inv-r* (i->fe am)) (f->i *inv-r*)))))
;; SECP-INV (mod p) uses it — speeds jac->affine, the Shamir precompute's affine
;; point-add, the reference point.lisp helpers, and the wNAF table normalize.
(defun secp-inv (a) (fast-inv a))

;;; ===========================================================================
;;; Scalar field F_n inverse — Montgomery arithmetic + Fermat addition chain.
;;; The portable secp-inv-mod (extended-Euclid bignums) was the single biggest
;;; allocator in ECDSA verify (~43 KB / verify of churn → GC-bound on many cores).
;;; n is not a Solinas-friendly prime, so we use Montgomery: %mul256 for the
;;; 512-bit product + %montredn (SOS reduction, n's limbs baked in) for R^-1.
;;; All on fixed limb buffers → zero per-op allocation; verified bit-for-bit vs
;;; the bignum inverse.  Window-free square-and-multiply over e = n-2.
;;; ===========================================================================
(defconstant +n-minus-2+ (- #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 2))
(defvar *mont-scratch* (make-array 9 :element-type '(unsigned-byte 64) :initial-element 0))
(defvar *nR*    (i->fe #x14551231950B75FC4402DA1732FC9BEBF))                                 ; R   mod n = mont(1)
(defvar *nR2*   (i->fe #x9D671CD581C69BC5E697F5E45BCD07C6741496C20E7CF878896CF21467D7D140))   ; R^2 mod n
(defvar *n-acc* (mkfe)) (defvar *n-base* (mkfe)) (defvar *n-out* (mkfe))

(declaim (inline nmul! nsqr!))
(defun nmul! (out a b)
  "out = a*b*R^-1 mod n (Montgomery product)."
  (declare (type fe out a b) (optimize (speed 3) (safety 0)))
  (sb-sys:with-pinned-objects (a b out *mont-scratch*)
    (%mul256 (sb-sys:vector-sap a) (sb-sys:vector-sap b) (sb-sys:vector-sap *mont-scratch*))
    (%montredn (sb-sys:vector-sap *mont-scratch*) (sb-sys:vector-sap out))))
(defun nsqr! (out a) (nmul! out a a))

(defun n-inv! (out a)
  "out = a^-1 mod n (fe, assumes 0 < a < n).  a^(n-2) via Montgomery exponentiation."
  (declare (type fe out a) (optimize (speed 3) (safety 0)))
  (nmul! *n-base* a *nR2*)             ; base = aR   (into Montgomery form)
  (fcopy! *n-acc* *nR*)                ; acc  = R = mont(1)
  (loop for bit fixnum from (1- (integer-length +n-minus-2+)) downto 0 do
    (nsqr! *n-acc* *n-acc*)
    (when (logbitp bit +n-minus-2+) (nmul! *n-acc* *n-acc* *n-base*)))
  (nmul! out *n-acc* *one-fe*))        ; acc * 1 * R^-1  (out of Montgomery form)

;; Redefine the scalar inverse: fast Montgomery path for the curve order n
;; (the only modulus ECDSA uses); portable extended-Euclid kept for any other m.
(defun secp-inv-mod (a m)
  (if (= m *secp256k1-n*)
      (let ((am (mod a m)))
        (if (zerop am) 0 (progn (n-inv! *n-out* (i->fe am)) (f->i *n-out*))))
      (let ((t0 0) (t1 1) (r0 m) (r1 (mod a m)))
        (loop while (not (zerop r1)) do
          (let* ((q (floor r0 r1)) (nr (- r0 (* q r1))) (nt (- t0 (* q t1))))
            (setf r0 r1 r1 nr t0 t1 t1 nt)))
        (if (< t0 0) (+ t0 m) t0))))

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

(defun glv-mul-2-naf (k1 px1 py1 k2 px2 py2)
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

;;; wNAF with a STATIC precomputed table for the generator G (and lambda*G).
;;; In every verify, p1 is G (ECDSA/Schnorr both call secp-mul-2 with the
;;; generator), so the G-side gets windowed recoding (fewer additions) with NO
;;; per-verify table build / inverse — the win without the cost.  Window 6 →
;;; 16-entry table, NAF (window 2) density 1/3 -> wNAF density 1/7 on the G side.
(defconstant +gwnaf-w+ 6)
(defvar *gtab* nil)   ; (gx[] gy[] gny[] lgx[]) affine odd multiples of G; λG shares y
(defun build-gtab ()
  (secp-init)
  (let* ((cnt (ash 1 (- +gwnaf-w+ 2))) (g (secp-generator)) (g2 (secp-add-points g g))
         (gx (make-array cnt)) (gy (make-array cnt)) (gny (make-array cnt)) (lgx (make-array cnt))
         (beta #x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee) (cur g))
    (dotimes (j cnt)
      (setf (aref gx j) (i->fe (secp-x cur)) (aref gy j) (i->fe (secp-y cur))
            (aref gny j) (i->fe (negy-int (secp-y cur)))
            (aref lgx j) (i->fe (secp-mod (* beta (secp-x cur)))))
      (setf cur (secp-add-points cur g2)))
    (setf *gtab* (list gx gy gny lgx))))

(defun wnaf (k w)
  "Width-w NAF: signed odd digits (and 0), index 0 = bit 0, density ~1/(w+1)."
  (let ((d (make-array (+ 2 (integer-length k)) :element-type 'fixnum :initial-element 0)) (i 0) (kk k)
        (m (ash 1 w)) (mh (ash 1 (1- w))))
    (loop while (plusp kk) do
      (if (oddp kk) (let ((z (mod kk m))) (when (>= z mh) (decf z m)) (setf (aref d i) z) (decf kk z))
          (setf (aref d i) 0))
      (setf kk (ash kk -1)) (incf i))
    (values d i)))

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

(defvar *wx* (mkfe)) (defvar *wy* (mkfe)) (defvar *wz* (mkfe))
;;; per-thread reusable buffers for the verify hot path (glv-mul-2-gwnaf):
;;; 4 NAF digit buffers (sub-scalars < 2^128 → length ≤ ~130) + Q-side fe's.
(defvar *nba* (make-array 136 :element-type 'fixnum :initial-element 0))
(defvar *nbb* (make-array 136 :element-type 'fixnum :initial-element 0))
(defvar *nbc* (make-array 136 :element-type 'fixnum :initial-element 0))
(defvar *nbd* (make-array 136 :element-type 'fixnum :initial-element 0))
(defvar *q2x* (mkfe)) (defvar *q2lx* (mkfe)) (defvar *q2y* (mkfe)) (defvar *q2ny* (mkfe))

(defun glv-mul-2-gwnaf (u1 k2 px2 py2)
  "u1*G + k2*(px2,py2): G-side via static wNAF table, Q-side via NAF.  ~128 dbl."
  (declare (optimize (speed 3) (safety 0)))
  (unless *gtab* (build-gtab))
  (multiple-value-bind (ma na mb nb) (glv-split u1)
    (multiple-value-bind (mc nc md nd) (glv-split k2)
      (destructuring-bind (gx gy gny lgx) *gtab*
        (let* ((x2 *q2x*) (lx2 *q2lx*) (y2 *q2y*) (ny2 *q2ny*))
          (i->fe! x2 px2) (i->fe! y2 py2) (i->fe! ny2 (negy-int py2))
          (fmul! lx2 (glv-beta) x2)
          (let ((yc+ (if nc ny2 y2)) (yc- (if nc y2 ny2)) (yd+ (if nd ny2 y2)) (yd- (if nd y2 ny2)))
            (let ((da *nba*) (la (wnaf-into ma +gwnaf-w+ *nba*)) (db *nbb*) (lb (wnaf-into mb +gwnaf-w+ *nbb*))
                  (dc *nbc*) (lc (naf-into mc *nbc*)) (dd *nbd*) (ld (naf-into md *nbd*)))
              (fill *wx* 0) (fill *wy* 0) (fill *wz* 0)
              (loop for i fixnum from (1- (max la lb lc ld)) downto 0 do
                (jdbl! *wx* *wy* *wz*)
                (when (< i la) (let ((e (aref da i)))
                  (unless (zerop e) (let ((j (ash (1- (abs e)) -1)))
                    (if (eq (> e 0) (not na)) (jadd! *wx* *wy* *wz* (aref gx j) (aref gy j))
                                              (jadd! *wx* *wy* *wz* (aref gx j) (aref gny j)))))))
                (when (< i lb) (let ((e (aref db i)))
                  (unless (zerop e) (let ((j (ash (1- (abs e)) -1)))
                    (if (eq (> e 0) (not nb)) (jadd! *wx* *wy* *wz* (aref lgx j) (aref gy j))
                                              (jadd! *wx* *wy* *wz* (aref lgx j) (aref gny j)))))))
                (when (< i lc) (let ((e (aref dc i)))
                  (cond ((= e 1) (jadd! *wx* *wy* *wz* x2 yc+)) ((= e -1) (jadd! *wx* *wy* *wz* x2 yc-)))))
                (when (< i ld) (let ((e (aref dd i)))
                  (cond ((= e 1) (jadd! *wx* *wy* *wz* lx2 yd+)) ((= e -1) (jadd! *wx* *wy* *wz* lx2 yd-))))))
              (jac->affine-int *wx* *wy* *wz*))))))))

(defun glv-mul-2 (k1 px1 py1 k2 px2 py2)
  "Dispatch: G-side static-wNAF when p1 is the generator (the verify case),
   else the general GLV+NAF path."
  (if (and (= px1 *secp256k1-gx*) (= py1 *secp256k1-gy*))
      (glv-mul-2-gwnaf k1 k2 px2 py2)
      (glv-mul-2-naf k1 px1 py1 k2 px2 py2)))

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

;;; ===========================================================================
;;; Reentrancy for multicore verify.  The scalar-mult scratch buffers above are
;;; module-level (fast, zero per-op allocation), which means a single thread at a
;;; time.  WITH-FRESH-SCRATCH rebinds them all to fresh per-thread arrays for its
;;; dynamic extent — wrap each worker thread's verify loop in it and verification
;;; (embarrassingly parallel) scales across cores.  Single-threaded callers use
;;; the module globals unchanged (no per-call cost).  The static G table (*gtab*,
;;; *glv-beta*) is read-only after build, so it's shared safely — built eagerly
;;; below to avoid a first-call race.
;;; ===========================================================================

(defmacro with-fresh-scratch (&body body)
  `(let ((*fmul-scratch* (make-array 8 :element-type '(unsigned-byte 64)))
         (*inv-r* (mkfe))
         (*ivx2* (mkfe)) (*ivx3* (mkfe)) (*ivx6* (mkfe)) (*ivx9* (mkfe)) (*ivx11* (mkfe))
         (*ivx22* (mkfe)) (*ivx44* (mkfe)) (*ivx88* (mkfe)) (*ivx176* (mkfe))
         (*ivx220* (mkfe)) (*ivx223* (mkfe))
         (*tA* (mkfe)) (*tB* (mkfe)) (*tC* (mkfe)) (*tD* (mkfe)) (*tE* (mkfe)) (*tF* (mkfe)) (*tG* (mkfe))
         (*aZZ* (mkfe)) (*aU2* (mkfe)) (*aS2* (mkfe)) (*aH* (mkfe)) (*aRR* (mkfe))
         (*aHH* (mkfe)) (*aI* (mkfe)) (*aJ* (mkfe)) (*aV* (mkfe)) (*aT* (mkfe))
         (*gx* (mkfe)) (*gy* (mkfe)) (*gz* (mkfe))
         (*wx* (mkfe)) (*wy* (mkfe)) (*wz* (mkfe))
         (*nba* (make-array 136 :element-type 'fixnum :initial-element 0))
         (*nbb* (make-array 136 :element-type 'fixnum :initial-element 0))
         (*nbc* (make-array 136 :element-type 'fixnum :initial-element 0))
         (*nbd* (make-array 136 :element-type 'fixnum :initial-element 0))
         (*q2x* (mkfe)) (*q2lx* (mkfe)) (*q2y* (mkfe)) (*q2ny* (mkfe))
         (*mont-scratch* (make-array 9 :element-type '(unsigned-byte 64) :initial-element 0))
         (*n-acc* (mkfe)) (*n-base* (mkfe)) (*n-out* (mkfe)))
     ,@body))

;; Build the static generator wNAF table now (read-only thereafter → race-free).
(build-gtab)
