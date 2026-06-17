;;;; hmac.lisp — HMAC-SHA256 (RFC 2104), built on our SHA-256.

(in-package #:secp256k1-fast.hash)

(defun hmac-sha256 (key msg)
  "HMAC-SHA256 of MSG under KEY (both byte vectors) → fresh 32-byte digest."
  (let* ((bs 64)
         (k (if (> (length key) bs) (sha256 key) key))
         (k0 (make-array bs :element-type '(unsigned-byte 8) :initial-element 0))
         (ipad (make-array bs :element-type '(unsigned-byte 8)))
         (opad (make-array bs :element-type '(unsigned-byte 8))))
    (replace k0 k)
    (dotimes (i bs)
      (setf (aref ipad i) (logxor (aref k0 i) #x36)
            (aref opad i) (logxor (aref k0 i) #x5c)))
    (let ((inner (sha256 (concatenate '(simple-array (unsigned-byte 8) (*)) ipad msg))))
      (sha256 (concatenate '(simple-array (unsigned-byte 8) (*)) opad inner)))))
