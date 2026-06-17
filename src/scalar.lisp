;;;; scalar.lisp — secp256k1 scalar field F_n, n = curve order.
;;;;
;;;; Used inside ECDSA (k^-1, etc.) where arithmetic is mod n, not mod p.

(in-package #:secp256k1-fast)

(defun secp-inv-mod (a m)
  "Modular inverse of A mod M (extended Euclidean) — used with M = n."
  (let ((t0 0) (t1 1) (r0 m) (r1 (mod a m)))
    (loop while (not (zerop r1)) do
      (let* ((q (floor r0 r1))
             (nr (- r0 (* q r1)))
             (nt (- t0 (* q t1))))
        (setf r0 r1 r1 nr t0 t1 t1 nt)))
    (if (< t0 0) (+ t0 m) t0)))
