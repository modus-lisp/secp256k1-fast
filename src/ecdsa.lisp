;;;; ecdsa.lisp — ECDSA over secp256k1 with RFC 6979 deterministic nonces.
;;;;
;;;; RFC 6979 derives k from (privkey, message hash) via HMAC-SHA256, so
;;;; signatures are reproducible and match every other RFC6979 signer.

(in-package #:secp256k1-fast)

(defun bytes-mod-n (bytes n) (mod (bytes-to-int bytes) n))
(defun bytes2octets (b n) (int-to-bytes32 (bytes-mod-n b n)))

(defun %cat (&rest arrays)
  (let* ((total (loop for a in arrays sum (length a)))
         (out (make-array total :element-type '(unsigned-byte 8)))
         (p 0))
    (dolist (a arrays out)
      (loop for b across a do (setf (aref out p) b) (incf p)))))

(defun rfc6979-k (privkey-int hash-bytes &optional n)
  "Deterministic nonce k in [1, n-1] per RFC 6979 §3.2."
  (secp-init)
  (let* ((n (or n *secp256k1-n*))
         (x (int-to-bytes32 privkey-int))
         (h1-octets (bytes2octets hash-bytes n))
         (v (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x01))
         (k (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x00)))
    (setf k (sha:hmac-sha256 k (%cat v #(#x00) x h1-octets)))
    (setf v (sha:hmac-sha256 k v))
    (setf k (sha:hmac-sha256 k (%cat v #(#x01) x h1-octets)))
    (setf v (sha:hmac-sha256 k v))
    (loop
      (setf v (sha:hmac-sha256 k v))
      (let ((candidate (bytes-to-int v)))
        (when (and (plusp candidate) (< candidate n)) (return candidate)))
      (setf k (sha:hmac-sha256 k (%cat v #(#x00))))
      (setf v (sha:hmac-sha256 k v)))))

(defun ecdsa-sign-raw (privkey-int hash-bytes)
  "Sign HASH-BYTES (32-byte digest) under PRIVKEY-INT.  Returns (values r s v),
   S canonicalized to low-S (BIP-62), V the 0/1 recovery id."
  (secp-init)
  (let* ((n *secp256k1-n*)
         (z (mod (bytes-to-int hash-bytes) n)))
    (loop
      (let* ((k (rfc6979-k privkey-int hash-bytes))
             (kg (ct-mul-g k))                 ; constant-time nonce point
             (r (mod (secp-x kg) n)))
        (when (zerop r) (return-from ecdsa-sign-raw nil))
        (let* ((k-inv (mod (secp-inv-mod k n) n))               ; secp-inv-mod is constant-time for n
               (s (ct-nmul k-inv (mod (+ z (ct-nmul r privkey-int)) n))))
          (when (zerop s) (return-from ecdsa-sign-raw nil))
          (let* ((y (secp-y kg))
                 (high-s? (> s (ash n -1)))
                 (s-can (if high-s? (- n s) s))
                 (v0 (if (oddp y) 1 0))
                 (v (if high-s? (logxor v0 1) v0)))
            (return (values r s-can v))))))))

(defun ecdsa-verify (pubkey-pt hash-bytes r s)
  "Verify (R, S) against HASH-BYTES under PUBKEY-PT.  Returns T or NIL."
  (secp-init)
  (let ((n *secp256k1-n*))
    (cond
      ((not (and (< 0 r n) (< 0 s n))) nil)
      (t
       (let* ((z (mod (bytes-to-int hash-bytes) n))
              (s-inv (secp-inv-mod s n))
              (u1 (mod (* z s-inv) n))
              (u2 (mod (* r s-inv) n))
              (sum (secp-mul-2 u1 (secp-generator) u2 pubkey-pt)))   ; Shamir's trick
         (and (not (secp-inf-p sum))
              (= r (mod (secp-x sum) n))))))))
