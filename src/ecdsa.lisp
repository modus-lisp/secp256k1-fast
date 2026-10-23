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

;;; RFC6979-K and ECDSA-SIGN-RAW take a private key, so they live in secret.lisp.

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
