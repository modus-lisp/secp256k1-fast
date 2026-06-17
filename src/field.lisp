;;;; field.lisp — secp256k1 base field F_p, p = 2^256 - 2^32 - 977.
;;;;
;;;; This is the PORTABLE INTEGER REFERENCE.  It is intentionally the narrow
;;;; waist of the library: a fast backend (SBCL VOPs operating on 4x64-bit limbs,
;;;; or MVM-native code using mul64lo/mul64hi/acc128 + Solinas reduction) replaces
;;;; SECP-MUL / SECP-SQ / SECP-INV here, and everything above is unchanged.  The
;;;; reference stays as the differential oracle the fast path is checked against.

(in-package #:secp256k1-fast)

(defparameter *secp256k1-p* nil)
(defparameter *secp256k1-n* nil)
(defparameter *secp256k1-gx* nil)
(defparameter *secp256k1-gy* nil)

(defun bytes-to-int (bytes)
  "Big-endian byte vector → integer."
  (let ((result 0))
    (dotimes (i (length bytes))
      (setf result (+ (ash result 8) (aref bytes i))))
    result))

(defun int-to-bytes32 (n)
  "Integer → 32-byte big-endian vector."
  (let ((result (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i 32)
      (setf (aref result (- 31 i)) (ldb (byte 8 (* i 8)) n)))
    result))

(defun mod-expt (base exp m)
  "Modular exponentiation base^exp mod m (square-and-multiply)."
  (let ((result 1) (b (mod base m)) (e exp))
    (loop while (plusp e) do
      (when (oddp e) (setf result (mod (* result b) m)))
      (setf e (ash e -1) b (mod (* b b) m)))
    result))

(defun secp-init ()
  "Initialize curve constants from canonical big-endian byte arrays (idempotent)."
  (unless *secp256k1-p*
    (setf *secp256k1-p*
          (bytes-to-int #(#xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFE #xFF #xFF #xFC #x2F)))
    (setf *secp256k1-n*
          (bytes-to-int #(#xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
                          #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFE
                          #xBA #xAE #xDC #xE6 #xAF #x48 #xA0 #x3B
                          #xBF #xD2 #x5E #x8C #xD0 #x36 #x41 #x41)))
    (setf *secp256k1-gx*
          (bytes-to-int #(#x79 #xBE #x66 #x7E #xF9 #xDC #xBB #xAC
                          #x55 #xA0 #x62 #x95 #xCE #x87 #x0B #x07
                          #x02 #x9B #xFC #xDB #x2D #xCE #x28 #xD9
                          #x59 #xF2 #x81 #x5B #x16 #xF8 #x17 #x98)))
    (setf *secp256k1-gy*
          (bytes-to-int #(#x48 #x3A #xDA #x77 #x26 #xA3 #xC4 #x65
                          #x5D #xA4 #xFB #xFC #x0E #x11 #x08 #xA8
                          #xFD #x17 #xB4 #x48 #xA6 #x85 #x54 #x19
                          #x9C #x47 #xD0 #x8F #xFB #x10 #xD4 #xB8))))
  t)

;;; --- F_p arithmetic --------------------------------------------------------
;;; The fast backend slots in here.

(defun secp-mod (x) (mod x *secp256k1-p*))
(defun secp-add (a b) (secp-mod (+ a b)))
(defun secp-sub (a b) (secp-mod (- a b)))
(defun secp-mul (a b) (secp-mod (* a b)))
(defun secp-sq  (a)   (secp-mod (* a a)))
(defun secp-neg (a)   (secp-mod (- *secp256k1-p* a)))

(defun secp-inv (a)
  "Modular inverse mod p via the extended Euclidean algorithm."
  (let ((t0 0) (t1 1)
        (r0 *secp256k1-p*) (r1 (mod a *secp256k1-p*)))
    (loop while (not (zerop r1)) do
      (let* ((q (floor r0 r1))
             (new-r1 (- r0 (* q r1)))
             (new-t1 (- t0 (* q t1))))
        (setf r0 r1 r1 new-r1 t0 t1 t1 new-t1)))
    (if (< t0 0) (+ t0 *secp256k1-p*) t0)))
