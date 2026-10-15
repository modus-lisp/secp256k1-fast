;;;; fe-modus.lisp — the limb field layer on modus: 5x52-bit FIXNUM limbs.
;;;;
;;;; Loaded on modus (feature :MODUS-MUL-SPLIT) in place of fe-sbcl.lisp, before
;;;; field-limb.lisp, and supplies the same interface — FE, MKFE, FMUL! FSQR!
;;;; FADD! FSUB! FDBL! FCOPY! FZERO? I->FE I->FE! F->I, the Montgomery product
;;;; mod n NMUL!/NSQR! with *NR* *NR2*, and NAF-INTO / WNAF-INTO — so the point
;;;; layer above it (Jacobian ops, GLV, wNAF, the addition-chain inverse) and the
;;;; constant-time paths in ct.lisp run unchanged.
;;;;
;;;; Why not 4x64: a modus fixnum is 62 bits, so a 64-bit limb is a bignum, and so
;;;; is every limb product through CL `*'.  This is libsecp256k1's field_5x52
;;;; layout instead: value = sum n_i 2^(52 i), and each 52x52-bit limb product is
;;;; taken by modus's %MUL-SPLIT-LO / %MUL-SPLIT-HI intrinsic — one 64x64->128
;;;; multiply, returning bits [0,52) and the product >> 52, both fixnums.  (natrium
;;;; does the same for GF(2^255-19).)  Nothing conses but the arrays themselves.
;;;;
;;;; REPRESENTATION.  Every operation returns a WEAKLY NORMALIZED element: limbs
;;;; 0..3 < 2^52 and limb 4 <= 2^48, so the value is < 2^256 + 2^52, congruent to
;;;; the result mod p but not necessarily < p.  Every input is assumed weakly
;;;; normalized.  FZERO? and F->I normalize fully.  All of it is a fixed sequence
;;;; of fixnum operations — no branch, index or count depends on a value — so the
;;;; constant-time structure ct.lisp relies on holds here too (at the algorithm
;;;; and field level; like the SBCL backend, not a formal guarantee in a GC'd
;;;; runtime).
;;;;
;;;; BOUNDS, because every sum must stay a fixnum (< 2^61).  Below, "lo" and "hi"
;;;; are the two halves of a product split at 52.
;;;;   FMUL!: limb products < 2^104 -> lo, hi < 2^52; five per column, so a
;;;;   column's lo-sum and hi-sum are each < 2^55, and T_k = lo_k + hi_(k-1) < 2^56.
;;;;   T_5..T_9 sit at 2^260 and up; 2^260 = R = #x1000003D10 (< 2^37) mod p, so
;;;;   T_(k+5)*R (< 2^93) is split again: lo to limb k, hi (< 2^41) to limb k+1.
;;;;   Limbs are then < 2^57.  After one carry pass the part at 2^256 is
;;;;   (limb4 >> 48) + (overflow << 4) < 2^46; times C = 2^256 mod p (< 2^33) it
;;;;   is split a third time.  A last carry pass leaves the weak form.
;;;;   FADD!/FSUB!: limbs < 2^55 (FSUB! adds 4p limb-wise, every limb of which is
;;;;   larger than the matching limb of a weak element), so the part at 2^256 is
;;;;   < 2^12 and its product with C a plain fixnum.

(in-package #:secp256k1-fast)

(defconstant +m52+ #xFFFFFFFFFFFFF "2^52 - 1.")
(defconstant +m48+ #xFFFFFFFFFFFF "2^48 - 1.")
(defconstant +fe-c+ #x1000003D1 "2^256 mod p.")
(defconstant +fe-r+ #x1000003D10 "2^260 mod p.")

(deftype fe () '(simple-array t (5)))
(defun mkfe () (make-array 5 :initial-element 0))

;;; WITH-FRESH-SCRATCH (field-limb.lisp) rebinds these for the SBCL backend's
;;; VOP buffers.  This backend keeps its intermediates in locals and needs none.
(defvar *fmul-scratch* nil)
(defvar *mont-scratch* nil)

;;; Every element argument is DECLARED a (simple-array t (5)): modus then reads
;;; and writes its limbs as raw word slots.  Undeclared, each SVREF is the
;;; general AREF (displaced/string/wrapper dispatch and out-of-line calls): 12 KB
;;; of bytecode for a two-limb add.

(defmacro %lo (a b) `(%mul-split-lo ,a ,b 52))
(defmacro %hi (a b) `(%mul-split-hi ,a ,b 52))

(defmacro %carry52 (from to)
  "Move FROM's bits above 52 into TO."
  `(setq ,to (+ ,to (ash ,from -52)) ,from (logand ,from +m52+)))

(defmacro %weak-normalize (l0 l1 l2 l3 l4)
  "Carry five limb VARIABLES (each < 2^56, the part at 2^256 times C a fixnum)
   to the weak form: limbs 0..3 < 2^52, limb 4 <= 2^48."
  `(progn
     (%carry52 ,l0 ,l1) (%carry52 ,l1 ,l2) (%carry52 ,l2 ,l3) (%carry52 ,l3 ,l4)
     (setq ,l0 (+ ,l0 (* (ash ,l4 -48) +fe-c+)) ,l4 (logand ,l4 +m48+))
     (%carry52 ,l0 ,l1) (%carry52 ,l1 ,l2) (%carry52 ,l2 ,l3)
     (setq ,l4 (+ ,l4 (ash ,l3 -52)) ,l3 (logand ,l3 +m52+))))

(defmacro %store5 (out l0 l1 l2 l3 l4)
  `(progn (setf (svref ,out 0) ,l0 (svref ,out 1) ,l1 (svref ,out 2) ,l2
                (svref ,out 3) ,l3 (svref ,out 4) ,l4)
          ,out))

(defmacro %with-limbs ((&rest names) fe &body body)
  `(let ,(loop for n in names for i from 0 collect `(,n (svref ,fe ,i)))
     ,@body))

;;; --- multiply -------------------------------------------------------------
(defmacro %fmul-body (out a b)
  "The product of the weak elements A and B into OUT (see BOUNDS).  Expanded
   once per caller so FMUL! and FSQR! are each one straight-line function."
  (let ((as (loop for i below 5 collect (intern (format nil "A~D" i))))
        (bs (loop for i below 5 collect (intern (format nil "B~D" i))))
        (ls (loop for k below 9 collect (intern (format nil "L~D" k))))
        (hs (loop for k below 9 collect (intern (format nil "H~D" k))))
        (ts (loop for k below 10 collect (intern (format nil "T~D" k))))
        (us (loop for k below 6 collect (intern (format nil "U~D" k)))))
    `(%with-limbs ,as ,a
       (%with-limbs ,bs ,b
         (let (,@(loop for v in (append ls hs) collect `(,v 0)))
           ;; column k of the schoolbook product, as (lo, hi) split at 52
           ,@(loop for i below 5 append
               (loop for j below 5
                     collect `(setq ,(nth (+ i j) ls) (+ ,(nth (+ i j) ls) (%lo ,(nth i as) ,(nth j bs)))
                                    ,(nth (+ i j) hs) (+ ,(nth (+ i j) hs) (%hi ,(nth i as) ,(nth j bs))))))
           (let* (,@(loop for k below 10
                          collect `(,(nth k ts)
                                    ,(cond ((= k 0) (first ls))
                                           ((= k 9) (nth 8 hs))
                                           (t `(+ ,(nth k ls) ,(nth (1- k) hs))))))
                  ;; fold T_5..T_9 (weight 2^260 and up) back by R = 2^260 mod p
                  ,@(loop for k below 6
                          collect `(,(nth k us)
                                    ,(cond ((= k 0) `(+ ,(nth 0 ts) (%lo ,(nth 5 ts) +fe-r+)))
                                           ((= k 5) `(%hi ,(nth 9 ts) +fe-r+))
                                           (t `(+ ,(nth k ts) (%lo ,(nth (+ k 5) ts) +fe-r+)
                                                  (%hi ,(nth (+ k 4) ts) +fe-r+)))))))
             (declare (ignorable ,(nth 0 ts)))
             (let ((u0 ,(nth 0 us)) (u1 ,(nth 1 us)) (u2 ,(nth 2 us))
                   (u3 ,(nth 3 us)) (u4 ,(nth 4 us)) (top 0))
               (%carry52 u0 u1) (%carry52 u1 u2) (%carry52 u2 u3) (%carry52 u3 u4)
               ;; everything at 2^256 and up, times C = 2^256 mod p, split once more
               (setq top (+ (ash u4 -48) (ash ,(nth 5 us) 4)) u4 (logand u4 +m48+))
               (setq u0 (+ u0 (%lo top +fe-c+)) u1 (+ u1 (%hi top +fe-c+)))
               (%carry52 u0 u1) (%carry52 u1 u2) (%carry52 u2 u3)
               (setq u4 (+ u4 (ash u3 -52)) u3 (logand u3 +m52+))
               (%store5 ,out u0 u1 u2 u3 u4))))))))

(defun fmul! (out a b)
  "OUT = A*B mod p (weak).  OUT may be A or B."
  (declare (type (simple-array t (5)) out a b))
  (%fmul-body out a b))

(defun fsqr! (out a)
  "OUT = A^2 mod p (weak)."
  (declare (type (simple-array t (5)) out a))
  (%fmul-body out a a))

;;; --- add / sub ------------------------------------------------------------
(defun fadd! (out a b)
  "OUT = A+B mod p (weak)."
  (declare (type (simple-array t (5)) out a b))
  (let ((l0 (+ (svref a 0) (svref b 0))) (l1 (+ (svref a 1) (svref b 1)))
        (l2 (+ (svref a 2) (svref b 2))) (l3 (+ (svref a 3) (svref b 3)))
        (l4 (+ (svref a 4) (svref b 4))))
    (%weak-normalize l0 l1 l2 l3 l4)
    (%store5 out l0 l1 l2 l3 l4)))

(defun fsub! (out a b)
  "OUT = A-B mod p (weak): A + 4p - B limb-wise, every limb non-negative."
  (declare (type (simple-array t (5)) out a b))
  (let ((l0 (- (+ (svref a 0) #x3FFFFBFFFFF0BC) (svref b 0)))
        (l1 (- (+ (svref a 1) #x3FFFFFFFFFFFFC) (svref b 1)))
        (l2 (- (+ (svref a 2) #x3FFFFFFFFFFFFC) (svref b 2)))
        (l3 (- (+ (svref a 3) #x3FFFFFFFFFFFFC) (svref b 3)))
        (l4 (- (+ (svref a 4) #x3FFFFFFFFFFFC) (svref b 4))))
    (%weak-normalize l0 l1 l2 l3 l4)
    (%store5 out l0 l1 l2 l3 l4)))

(defun fdbl! (out a) (fadd! out a a))

(defun fcopy! (out a)
  (declare (type (simple-array t (5)) out a))
  (%with-limbs (l0 l1 l2 l3 l4) a (%store5 out l0 l1 l2 l3 l4)))

;;; --- normalization --------------------------------------------------------
(defmacro %full-normalize (l0 l1 l2 l3 l4)
  "Reduce five weak limb VARIABLES to the canonical value in [0, p), branch-free.
   A weak value V is < 2p, so V mod p is V or V-p; V >= p exactly when V + C
   reaches 2^256 (C = 2^256 - p), and then V - p is V + C - 2^256."
  `(let ((w0 (+ ,l0 +fe-c+)) (w1 ,l1) (w2 ,l2) (w3 ,l3) (w4 ,l4) (mask 0))
     (%carry52 w0 w1) (%carry52 w1 w2) (%carry52 w2 w3)
     (setq w4 (+ w4 (ash w3 -52)) w3 (logand w3 +m52+))
     (setq mask (- (ash w4 -48))          ; all-ones iff V + C >= 2^256
           w4 (logand w4 +m48+))
     (setq ,l0 (logxor ,l0 (logand mask (logxor ,l0 w0)))
           ,l1 (logxor ,l1 (logand mask (logxor ,l1 w1)))
           ,l2 (logxor ,l2 (logand mask (logxor ,l2 w2)))
           ,l3 (logxor ,l3 (logand mask (logxor ,l3 w3)))
           ,l4 (logxor ,l4 (logand mask (logxor ,l4 w4))))))

(defun fzero? (a)
  "True if A is 0 mod p."
  (declare (type (simple-array t (5)) a))
  (%with-limbs (l0 l1 l2 l3 l4) a
    (%full-normalize l0 l1 l2 l3 l4)
    (zerop (logior l0 l1 l2 l3 l4))))

(defun i->fe! (out x)
  "OUT = the low 256 bits of the integer X, as limbs."
  (declare (type (simple-array t (5)) out))
  (%store5 out (logand x +m52+) (logand (ash x -52) +m52+) (logand (ash x -104) +m52+)
           (logand (ash x -156) +m52+) (logand (ash x -208) +m48+)))

(defun i->fe (x) (i->fe! (mkfe) x))

(defun f->i (a)
  "The canonical integer value of A, in [0, p)."
  (declare (type (simple-array t (5)) a))
  (%with-limbs (l0 l1 l2 l3 l4) a
    (%full-normalize l0 l1 l2 l3 l4)
    (logior l0 (ash l1 52) (ash l2 104) (ash l3 156) (ash l4 208))))

;;; --- Montgomery multiplication mod n --------------------------------------
;;; NMUL! is a*b*R^-1 mod n with R = 2^260 (the SBCL backend's R is 2^256; *NR*
;;; and *NR2* are this backend's R mod n and R^2 mod n, so N-INV! and CT-NMUL in
;;; the shared code are unchanged).  Operands are canonical scalars (< n) in the
;;; same 5x52 limbs.  Separated operand scanning: the 10-column product as in
;;; FMUL!, then five rounds each adding m*n*2^(52 i) with m = t_i * n' mod 2^52
;;; (n' = -n^-1 mod 2^52), which clears limb i; the result, < 2n, loses n by a
;;; masked subtract.  Column values stay below 2^57: < 2^56 from the product,
;;; plus at most two halves (< 2^52) per round.
(defconstant +n-prime+ #xDFF665588B13F "-n^-1 mod 2^52.")
(defvar *nR*  (i->fe #x14551231950B75FC4402DA1732FC9BEBF0))   ; 2^260 mod n = mont(1)
(defvar *nR2* (i->fe #x671CD581C69BC5E697F5E45BCD07C73B97594894FD6E33E4C8EE180C268B3B23)) ; 2^520 mod n

(defmacro %nmul-body (out a b)
  (let* ((nl '(#x25E8CD0364141 #xE6AF48A03BBFD #xFFFFFFEBAAEDC #xFFFFFFFFFFFFF #xFFFFFFFFFFFF))
         (as (loop for i below 5 collect (intern (format nil "A~D" i))))
         (bs (loop for i below 5 collect (intern (format nil "B~D" i))))
         (ts (loop for k below 10 collect (intern (format nil "T~D" k))))
         (rs (loop for k below 5 collect (nth (+ k 5) ts)))
         (ds (loop for k below 5 collect (intern (format nil "D~D" k)))))
    `(%with-limbs ,as ,a
       (%with-limbs ,bs ,b
         (let (,@(loop for v in ts collect `(,v 0)) (m 0) (mask 0)
               ,@(loop for v in ds collect `(,v 0)))
           ,@(loop for i below 5 append
               (loop for j below 5
                     collect `(setq ,(nth (+ i j) ts) (+ ,(nth (+ i j) ts) (%lo ,(nth i as) ,(nth j bs)))
                                    ,(nth (+ i j 1) ts) (+ ,(nth (+ i j 1) ts) (%hi ,(nth i as) ,(nth j bs))))))
           ,@(loop for i below 5 append
               `((setq m (%lo ,(nth i ts) +n-prime+))
                 ,@(loop for j below 5 for nj in nl
                         collect `(setq ,(nth (+ i j) ts) (+ ,(nth (+ i j) ts) (%lo m ,nj))
                                        ,(nth (+ i j 1) ts) (+ ,(nth (+ i j 1) ts) (%hi m ,nj))))
                 (setq ,(nth (1+ i) ts) (+ ,(nth (1+ i) ts) (ash ,(nth i ts) -52)))))
           ;; the result is T5..T9; carry it to limbs, T9 keeping the top
           (%carry52 ,(nth 0 rs) ,(nth 1 rs)) (%carry52 ,(nth 1 rs) ,(nth 2 rs))
           (%carry52 ,(nth 2 rs) ,(nth 3 rs)) (%carry52 ,(nth 3 rs) ,(nth 4 rs))
           ;; D = result - n with a signed borrow; keep the result iff D < 0
           (let ((c 0))
             ,@(loop for k below 4
                     collect `(setq ,(nth k ds) (+ (- ,(nth k rs) ,(nth k nl)) c)
                                    c (ash ,(nth k ds) -52)
                                    ,(nth k ds) (logand ,(nth k ds) +m52+)))
             (setq ,(nth 4 ds) (+ (- ,(nth 4 rs) ,(nth 4 nl)) c)))
           (setq mask (ash ,(nth 4 ds) -62))    ; all-ones iff result < n
           (%store5 ,out
                    ,@(loop for k below 5
                            collect `(logxor ,(nth k ds) (logand mask (logxor ,(nth k rs) ,(nth k ds)))))))))))

(defun nmul! (out a b)
  "OUT = A*B*2^-260 mod n (Montgomery product), canonical."
  (declare (type (simple-array t (5)) out a b))
  (%nmul-body out a b))

(defun nsqr! (out a) (nmul! out a a))

;;; --- scalar recoding ------------------------------------------------------
;;; NAF / wNAF of a sub-scalar K < 2^128 (verification only: public data, so
;;; variable time is fine).  The SBCL versions shift two (unsigned-byte 64)
;;; words, which are bignums here; these keep K as three 52-bit fixnum limbs.
(defmacro %k-limbs ((l0 l1 l2) k &body body)
  `(let ((,l0 (logand ,k +m52+)) (,l1 (logand (ash ,k -52) +m52+)) (,l2 (ash ,k -104)))
     ,@body))

(defmacro %k-add (l0 l1 l2 d)
  "K += D for a small (possibly negative) fixnum D, borrows and carries rippled."
  `(progn (setq ,l0 (+ ,l0 ,d))
          (cond ((minusp ,l0) (setq ,l0 (+ ,l0 (ash 1 52)) ,l1 (1- ,l1))
                 (when (minusp ,l1) (setq ,l1 (+ ,l1 (ash 1 52)) ,l2 (1- ,l2))))
                ((> ,l0 +m52+) (setq ,l0 (logand ,l0 +m52+) ,l1 (1+ ,l1))
                 (when (> ,l1 +m52+) (setq ,l1 (logand ,l1 +m52+) ,l2 (1+ ,l2)))))))

(defmacro %k-shift1 (l0 l1 l2)
  `(setq ,l0 (logior (ash ,l0 -1) (ash (logand ,l1 1) 51))
         ,l1 (logior (ash ,l1 -1) (ash (logand ,l2 1) 51))
         ,l2 (ash ,l2 -1)))

(defun naf-into (k buf)
  "NAF of K (< 2^128) into BUF -> length."
  (%k-limbs (l0 l1 l2) k
    (let ((i 0))
      (loop until (zerop (logior l0 l1 l2)) do
        (if (logbitp 0 l0)
            (let ((z (- 2 (logand l0 3))))
              (setf (aref buf i) z)
              (%k-add l0 l1 l2 (- z)))
            (setf (aref buf i) 0))
        (%k-shift1 l0 l1 l2)
        (incf i))
      i)))

(defun wnaf-into (k w buf)
  "Width-W NAF of K (< 2^128) into BUF -> length."
  (%k-limbs (l0 l1 l2) k
    (let ((i 0) (m (ash 1 w)) (mh (ash 1 (1- w))))
      (loop until (zerop (logior l0 l1 l2)) do
        (if (logbitp 0 l0)
            (let ((z (logand l0 (- m 1))))
              (when (>= z mh) (decf z m))
              (setf (aref buf i) z)
              (%k-add l0 l1 l2 (- z)))
            (setf (aref buf i) 0))
        (%k-shift1 l0 l1 l2)
        (incf i))
      i)))
