;;;; packages.lisp

(defpackage #:secp256k1-fast.hash
  (:use #:cl)
  (:documentation "Self-contained SHA-256 + HMAC-SHA256 (no external deps).")
  (:export #:sha256 #:hmac-sha256 #:ascii->bytes))

(defpackage #:secp256k1-fast
  (:use #:cl)
  (:local-nicknames (#:sha #:secp256k1-fast.hash))
  (:documentation "secp256k1 field / scalar / point arithmetic + ECDSA.
   Field arithmetic (FIELD.LISP) is the layer a fast VOP/MVM backend replaces;
   point math uses Jacobian coordinates + Shamir's trick.")
  (:export
   ;; constants + conversions + small number-theory helpers
   #:*secp256k1-p* #:*secp256k1-n* #:*secp256k1-gx* #:*secp256k1-gy*
   #:secp-init #:secp-generator #:bytes-to-int #:int-to-bytes32 #:mod-expt
   ;; field (mod p) and curve ops
   #:secp-mod #:secp-add #:secp-sub #:secp-mul #:secp-sq #:secp-neg #:secp-inv
   #:secp-double #:secp-add-points #:secp-mul-point #:secp-mul-2
   #:secp-on-curve-p #:secp-pubkey #:secp-inf-p #:secp-x #:secp-y
   ;; scalar (mod n)
   #:secp-inv-mod
   ;; ECDSA
   #:ecdsa-sign-raw #:ecdsa-verify #:rfc6979-k
   ;; reentrancy: bind the scalar-mult scratch per-thread for parallel verify
   #:with-fresh-scratch))

(defpackage #:secp256k1-fast.schnorr
  (:use #:cl)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:sha #:secp256k1-fast.hash))
  (:documentation "BIP340 Schnorr (Bitcoin taproot / Nostr event signatures).")
  (:export #:schnorr-sign #:schnorr-verify #:tagged-hash #:pubkey-xonly #:lift-x))
