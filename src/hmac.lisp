;;;; hmac.lisp — HMAC-SHA256, from natrium (see sha256.lisp).

(in-package #:secp256k1-fast.hash)

(defun hmac-sha256 (key msg)
  "HMAC-SHA256 of MSG under KEY → fresh 32-byte digest (HMAC-SHA256-INTO for secrets)."
  (natrium:hmac-sha256 key msg))

(defun hmac-sha256-into (key parts out &key (start 0)) (natrium:hmac-sha256-into key parts out :start start))
