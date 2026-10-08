;;;; ecdh.lisp -- secp256k1 keys, the FIPS-style ECDH, and the wire codec.
;;;;
;;;; Authority: upstream jmcorgan/fips @ 57bc510, src/noise/handshake.rs.
;;;;   * Public keys travel as 33-byte compressed SEC1 (PUBKEY_SIZE = 33,
;;;;     `PublicKey::serialize`).
;;;;   * `fn ecdh`: the shared secret is SHA-256 over the 32-byte X coordinate of
;;;;     the shared point only ("x-only hashing ... parity-independent").  This is
;;;;     NOT libsecp256k1's default ECDH hash (which hashes a parity byte too).
;;;;
;;;; Point arithmetic comes from secp256k1-fast (SECP-MUL-POINT, affine points
;;;; as (x . y) conses).  secp256k1-fast exposes no ECDH and no SEC1 codec, so
;;;; the thin layer lives here rather than being added to that library.
;;;;
;;;; The DH multiplies a SECRET scalar by a peer point, so it goes through
;;;; CT-MUL-POINT (fixed-window, complete-formula, constant-time table read) on
;;;; the limb backend.  On targets without that backend CT-MUL-POINT falls back
;;;; to the variable-time SECP-MUL-POINT (see point.lisp), like CT-MUL-G does.

(in-package #:secp256k1-fast.ecdh)

(defconstant +pubkey-size+ 33 "Compressed SEC1 public key (handshake.rs PUBKEY_SIZE).")

(defun u8 (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun u8-concat (&rest vs)
  (let* ((out (u8 (reduce #'+ vs :key #'length))) (pos 0))
    (dolist (v vs out)
      (replace out v :start1 pos)
      (incf pos (length v)))))

(defun u8-subseq (v start &optional end)
  (let ((s (subseq v start end)))
    (coerce s '(simple-array (unsigned-byte 8) (*)))))

(defun secp-p () (secp256k1-fast:secp-init) secp256k1-fast:*secp256k1-p*)
(defun secp-n () (secp256k1-fast:secp-init) secp256k1-fast:*secp256k1-n*)

;;; --- SEC1 compressed encoding ------------------------------------------------

(defun encode-pubkey (point)
  "Affine point (x . y) -> 33-byte compressed SEC1 (0x02 even y, 0x03 odd y)."
  (u8-concat (let ((b (u8 1))) (setf (aref b 0) (if (evenp (cdr point)) 2 3)) b)
             (secp256k1-fast:int-to-bytes32 (car point))))

(defun decode-pubkey (bytes)
  "33-byte compressed SEC1 -> affine point, or NIL if not a valid curve point
   (mirrors `PublicKey::from_slice` rejecting with NoiseError::InvalidPublicKey)."
  (when (and (= (length bytes) +pubkey-size+) (member (aref bytes 0) '(2 3)))
    (let* ((p (secp-p))
           (x (secp256k1-fast:bytes-to-int (u8-subseq bytes 1 33))))
      (when (< x p)
        (let* ((c (mod (+ (* x x x) 7) p))
               (y (secp256k1-fast:mod-expt c (floor (+ p 1) 4) p)))
          (when (= (mod (* y y) p) c)
            (let ((want-odd (= (aref bytes 0) 3)))
              (cons x (if (eq (oddp y) want-odd) y (- p y))))))))))

;;; --- Keys ------------------------------------------------------------------

(defstruct (keypair (:constructor %make-keypair (secret public)))
  secret     ; integer in [1, n-1]
  public)    ; affine point

(defun keypair-from-secret (secret-bytes)
  "Keypair from a 32-byte big-endian secret.  Errors on 0 or >= n, as
   `SecretKey::from_slice` does."
  (let ((k (secp256k1-fast:bytes-to-int secret-bytes)))
    (unless (and (= (length secret-bytes) 32) (< 0 k (secp-n)))
      (error "invalid secp256k1 secret key"))
    (%make-keypair k (secp256k1-fast:secp-pubkey k))))

(defun keypair-public-bytes (kp) (encode-pubkey (keypair-public kp)))

(defun ecdh-x (secret point)
  "32-byte X coordinate of SECRET * POINT.  Errors on the point at infinity."
  (let ((r (secp256k1-fast:ct-mul-point secret point)))
    (when (secp256k1-fast:secp-inf-p r) (error "ECDH produced the point at infinity"))
    (secp256k1-fast:int-to-bytes32 (car r))))

(defun noise-dh (keypair point)
  "The FIPS Noise DH (handshake.rs `fn ecdh`): SHA-256(x(secret * point))."
  (secp256k1-fast.hash:sha256 (ecdh-x (keypair-secret keypair) point)))
