;;;; sha256.lisp — SHA-256 for secp256k1-fast, from natrium.
;;;;
;;;; This library used to carry its own copy of SHA-256 and HMAC-SHA256.  Signing
;;;; hashes secret material (BIP-340's nonce derivation, RFC 6979's HMAC-DRBG over the
;;;; private key), and natrium's streaming SHA-2 keeps that material in fixed scratch
;;;; and never copies a message for padding; a second, consing copy here would undo
;;;; that.  One audited hash for the whole stack.

(in-package #:secp256k1-fast.hash)

(deftype u8v () '(simple-array (unsigned-byte 8) (*)))

(defun sha256 (msg)
  "SHA-256 of byte vector MSG → fresh 32-byte digest (use SHA256-INTO for secrets)."
  (natrium:sha256 msg))

(defun sha256-into (msg out &key (start 0)) (natrium:sha256-into msg out :start start))

(defun ascii->bytes (string)
  "ASCII STRING → (unsigned-byte 8) vector (for BIP340 tag literals)."
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))
