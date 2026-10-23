;;;; packages.lisp

(defpackage #:secp256k1-fast.hash
  (:use #:cl)
  (:documentation "SHA-256 + HMAC-SHA256 (natrium's streaming, fixed-scratch implementation).")
  (:export #:sha256 #:sha256-into #:hmac-sha256 #:hmac-sha256-into #:ascii->bytes))

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
   #:secp-sqrt-candidate
   #:secp-double #:secp-add-points #:secp-mul-point #:secp-mul-2
   #:secp-on-curve-p #:secp-pubkey #:secp-inf-p #:secp-x #:secp-y
   ;; constant-time multiply of a secret scalar by the base point G, and
   ;; constant-time scalar multiply mod n (secret operands in signing)
   #:ct-mul-g #:ct-mul-g-available-p #:ct-nmul
   #:ct-mul-point #:ct-mul-point-available-p #:with-fresh-ct-scratch
   ;; scalar (mod n)
   #:secp-inv-mod
   ;; ECDSA
   #:ecdsa-sign-raw #:ecdsa-verify #:rfc6979-k
   ;; private keys as fixed buffers (secret.lisp)
   #:seckey-valid-p #:seckey-tweak-add-into #:seckey-negate-into #:seckey-tweak-mul-into #:seckey-add-into #:seckey-compressed-pubkey
   ;; reentrancy: bind the scalar-mult scratch per-thread for parallel verify
   #:with-fresh-scratch))

(defpackage #:secp256k1-fast.schnorr
  (:use #:cl)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:sha #:secp256k1-fast.hash))
  (:documentation "BIP340 Schnorr (Bitcoin taproot / Nostr event signatures).")
  (:export #:schnorr-sign #:schnorr-verify #:tagged-hash #:pubkey-xonly #:lift-x))

(defpackage #:secp256k1-fast.ecdh
  (:use #:cl)
  (:documentation "secp256k1 keys, the FIPS ECDH (SHA-256 over the shared point's X
   coordinate), and the 33-byte compressed SEC1 codec used by FIPS Noise.
   Authority: upstream jmcorgan/fips @ 57bc510, src/noise/handshake.rs.")
  (:export
   #:+pubkey-size+ #:encode-pubkey #:decode-pubkey
   #:keypair #:keypair-secret #:keypair-public #:keypair-from-secret
   #:keypair-public-bytes #:keypair-wipe #:keypair-p #:ecdh-x #:ecdh-compressed-into #:noise-dh
   #:peer-point-valid-p #:ecdh-constant-time-p))
