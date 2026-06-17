;;;; point.lisp — secp256k1 group operations.
;;;;
;;;; Public points are affine: (x . y) conses, with the point at infinity as
;;;; (:infinity . nil).  Single add/double stay affine (one inverse each) — used
;;;; rarely.  The scalar-multiplication hot path runs in Jacobian projective
;;;; coordinates (x = X/Z^2, y = Y/Z^3; infinity = NIL) and converts back with a
;;;; single inverse:
;;;;   - SECP-MUL-POINT  k*P            (MSB-first double-and-add, mixed adds)
;;;;   - SECP-MUL-2      k1*P1 + k2*P2  (Shamir's trick: shared doublings)
;;;; SECP-MUL-2 is the ECDSA/Schnorr verify pattern (u1*G + u2*Q).

(in-package #:secp256k1-fast)

(defparameter *secp256k1-infinity* (cons :infinity nil))

(defun secp-inf-p (p) (eq (car p) :infinity))
(defun secp-x (p) (car p))
(defun secp-y (p) (cdr p))

(defun secp-double (p)
  "Affine point doubling."
  (when (secp-inf-p p) (return-from secp-double p))
  (let ((x (secp-x p)) (y (secp-y p)))
    (when (zerop y) (return-from secp-double *secp256k1-infinity*))
    (let* ((lam (secp-mul (secp-mul 3 (secp-sq x)) (secp-inv (secp-mul 2 y))))
           (x3 (secp-sub (secp-sq lam) (secp-mul 2 x)))
           (y3 (secp-sub (secp-mul lam (secp-sub x x3)) y)))
      (cons x3 y3))))

(defun secp-add-points (p1 p2)
  "Affine point addition."
  (cond
    ((secp-inf-p p1) p2)
    ((secp-inf-p p2) p1)
    (t
     (let ((x1 (secp-x p1)) (y1 (secp-y p1))
           (x2 (secp-x p2)) (y2 (secp-y p2)))
       (cond
         ((and (= x1 x2) (= y1 (secp-neg y2))) *secp256k1-infinity*)
         ((and (= x1 x2) (= y1 y2)) (secp-double p1))
         (t
          (let* ((lam (secp-mul (secp-sub y2 y1) (secp-inv (secp-sub x2 x1))))
                 (x3 (secp-sub (secp-sub (secp-sq lam) x1) x2))
                 (y3 (secp-sub (secp-mul lam (secp-sub x1 x3)) y1)))
            (cons x3 y3))))))))

;;; --- Jacobian coordinates (scalar-mult hot path) ---------------------------
;;; dbl-2009-l (a=0 doubling) and madd-2007-bl (mixed Jacobian + affine add).
;;; A Jacobian point is (X Y Z); infinity is NIL.

(declaim (inline jac-double jac-add-affine))

(defun jac-double (jp)
  (when (null jp) (return-from jac-double nil))
  (destructuring-bind (x y z) jp
    (if (zerop y)
        nil
        (let* ((a (secp-sq x)) (b (secp-sq y)) (c (secp-sq b))
               (d (secp-mul 2 (secp-sub (secp-sub (secp-sq (secp-add x b)) a) c)))
               (e (secp-mul 3 a)) (f (secp-sq e))
               (x3 (secp-sub f (secp-mul 2 d)))
               (y3 (secp-sub (secp-mul e (secp-sub d x3)) (secp-mul 8 c)))
               (z3 (secp-mul 2 (secp-mul y z))))
          (list x3 y3 z3)))))

(defun jac-add-affine (jp ax ay)
  (when (null jp) (return-from jac-add-affine (list ax ay 1)))
  (destructuring-bind (x1 y1 z1) jp
    (let* ((z1z1 (secp-sq z1))
           (u2 (secp-mul ax z1z1))
           (s2 (secp-mul ay (secp-mul z1 z1z1)))
           (h (secp-sub u2 x1))
           (rr (secp-sub s2 y1)))
      (cond
        ((zerop h) (if (zerop rr) (jac-double jp) nil))  ; same point → double; opposite → ∞
        (t (let* ((hh (secp-sq h)) (i (secp-mul 4 hh)) (j (secp-mul h i))
                  (r (secp-mul 2 rr)) (v (secp-mul x1 i))
                  (x3 (secp-sub (secp-sub (secp-sq r) j) (secp-mul 2 v)))
                  (y3 (secp-sub (secp-mul r (secp-sub v x3)) (secp-mul 2 (secp-mul y1 j))))
                  (z3 (secp-sub (secp-sub (secp-sq (secp-add z1 h)) z1z1) hh)))
             (list x3 y3 z3)))))))

(defun jac->affine (jp)
  "Convert Jacobian → affine — the single inverse per scalar mult."
  (if (null jp)
      *secp256k1-infinity*
      (destructuring-bind (x y z) jp
        (if (zerop z)
            *secp256k1-infinity*
            (let* ((zinv (secp-inv z)) (zinv2 (secp-sq zinv)))
              (cons (secp-mul x zinv2) (secp-mul y (secp-mul zinv2 zinv))))))))

(defun secp-mul-point (k p)
  "Scalar multiplication k*P (MSB-first double-and-add, Jacobian internal)."
  (secp-init)
  (if (secp-inf-p p)
      *secp256k1-infinity*
      (let ((n (mod k *secp256k1-n*)))
        (if (zerop n)
            *secp256k1-infinity*
            (let ((ax (secp-x p)) (ay (secp-y p)) (r nil))
              (loop for i fixnum from (1- (integer-length n)) downto 0 do
                (setf r (jac-double r))
                (when (logbitp i n) (setf r (jac-add-affine r ax ay))))
              (jac->affine r))))))

(defun secp-mul-2 (k1 p1 k2 p2)
  "Affine k1*P1 + k2*P2 via Shamir's trick — one shared chain of doublings for
   both scalars.  Bases must be finite; falls back to two mults otherwise."
  (secp-init)
  (when (or (secp-inf-p p1) (secp-inf-p p2))
    (return-from secp-mul-2
      (secp-add-points (secp-mul-point k1 p1) (secp-mul-point k2 p2))))
  (let* ((n1 (mod k1 *secp256k1-n*)) (n2 (mod k2 *secp256k1-n*))
         (x1 (secp-x p1)) (y1 (secp-y p1)) (x2 (secp-x p2)) (y2 (secp-y p2))
         (sum (secp-add-points p1 p2))             ; for the both-bits-set case
         (sum-inf (secp-inf-p sum))
         (sx (unless sum-inf (secp-x sum))) (sy (unless sum-inf (secp-y sum)))
         (r nil))
    (loop for i fixnum from (1- (max (integer-length n1) (integer-length n2))) downto 0 do
      (setf r (jac-double r))
      (let ((b1 (logbitp i n1)) (b2 (logbitp i n2)))
        (cond ((and b1 b2) (unless sum-inf (setf r (jac-add-affine r sx sy))))  ; +∞ is a no-op
              (b1 (setf r (jac-add-affine r x1 y1)))
              (b2 (setf r (jac-add-affine r x2 y2))))))
    (jac->affine r)))

(defun secp-generator ()
  (secp-init)
  (cons *secp256k1-gx* *secp256k1-gy*))

(defun secp-pubkey (privkey)
  "Public-key point from a private-key integer."
  (secp-mul-point privkey (secp-generator)))

(defun secp-on-curve-p (p)
  "Is P on y^2 = x^3 + 7?"
  (secp-init)
  (if (secp-inf-p p) t
      (let ((x (secp-x p)) (y (secp-y p)))
        (= (secp-sq y) (secp-mod (+ (secp-mul x (secp-sq x)) 7))))))
