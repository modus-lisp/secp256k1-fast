;;;; schnorr.lisp — BIP-340 Schnorr signatures over secp256k1.
;;;;
;;;; The scheme Bitcoin Taproot and Nostr event signatures use.  Points are the
;;;; (x . y) conses from POINT.LISP; hashing is our own SHA-256.  Verified
;;;; against the canonical BIP-340 test vectors (see test/).

(in-package #:secp256k1-fast.schnorr)

(defun cat (&rest vs) (apply #'concatenate '(vector (unsigned-byte 8)) vs))

(defun tagged-hash (tag msg)
  "BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."
  (let ((th (sha:sha256 (sha:ascii->bytes tag))))
    (sha:sha256 (cat th th msg))))

(defun p () secp:*secp256k1-p*)
(defun n () secp:*secp256k1-n*)

(defun lift-x (x)
  "BIP-340 lift_x: the point with even Y whose X is X, or NIL."
  (secp:secp-init)
  (when (and (>= x 0) (< x (p)))
    (let* ((c (secp:secp-mod (+ (secp:secp-mul (secp:secp-mul x x) x) 7)))
           (y (secp:mod-expt c (floor (+ (p) 1) 4) (p))))
      (when (= (secp:secp-mod (* y y)) c)
        (cons x (if (evenp y) y (- (p) y)))))))

(defun pubkey-xonly (privkey-int)
  "32-byte x-only public key for a private-key integer."
  (secp:secp-init)
  (secp:int-to-bytes32 (secp:secp-x (secp:secp-mul-point privkey-int (secp:secp-generator)))))

(defun schnorr-verify (pubkey32 msg32 sig64)
  "T iff SIG64 is a valid BIP-340 signature of MSG32 under x-only PUBKEY32."
  (secp:secp-init)
  (handler-case
      (let* ((px (secp:bytes-to-int pubkey32))
             (pt (lift-x px)))
        (when pt
          (let ((r (secp:bytes-to-int (subseq sig64 0 32)))
                (s (secp:bytes-to-int (subseq sig64 32 64))))
            (when (and (< r (p)) (< s (n)))
              (let* ((e (mod (secp:bytes-to-int
                              (tagged-hash "BIP0340/challenge"
                                           (cat (subseq sig64 0 32) pubkey32 msg32)))
                             (n)))
                     ;; R = s*G + (n-e)*P  via Shamir's trick
                     (rr (secp:secp-mul-2 s (secp:secp-generator) (mod (- (n) e) (n)) pt)))
                (and (not (secp:secp-inf-p rr))
                     (evenp (secp:secp-y rr))
                     (= (secp:secp-x rr) r)))))))
    (error () nil)))

(defun schnorr-sign (privkey-int msg32
                     &optional (aux (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
  "BIP-340 sign.  Returns a 64-byte signature."
  (secp:secp-init)
  (let* ((dp privkey-int)
         (pt (secp:secp-mul-point dp (secp:secp-generator)))
         (d (if (evenp (secp:secp-y pt)) dp (- (n) dp)))
         (px (secp:int-to-bytes32 (secp:secp-x pt)))
         (tt (logxor d (secp:bytes-to-int (tagged-hash "BIP0340/aux" aux))))
         (rand (tagged-hash "BIP0340/nonce" (cat (secp:int-to-bytes32 tt) px msg32)))
         (k0 (mod (secp:bytes-to-int rand) (n))))
    (when (zerop k0) (error "schnorr-sign: k=0"))
    (let* ((rpt (secp:secp-mul-point k0 (secp:secp-generator)))
           (k (if (evenp (secp:secp-y rpt)) k0 (- (n) k0)))
           (rx (secp:int-to-bytes32 (secp:secp-x rpt)))
           (e (mod (secp:bytes-to-int (tagged-hash "BIP0340/challenge" (cat rx px msg32))) (n)))
           (sig-s (secp:int-to-bytes32 (mod (+ k (* e d)) (n)))))
      (cat rx sig-s))))
