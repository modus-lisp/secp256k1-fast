;;;; test/test.lisp — self-contained correctness tests.

(defpackage #:secp256k1-fast.test
  (:use #:cl)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:schnorr #:secp256k1-fast.schnorr)
                    (#:sha #:secp256k1-fast.hash))
  (:export #:run-all #:cross-check #:bench #:thread-test))

(in-package #:secp256k1-fast.test)

(defvar *fail* 0)
(defun check (name got want)
  (let ((ok (equalp got want)))
    (format t "  [~a] ~a~%" (if ok "PASS" "FAIL") name)
    (unless ok (incf *fail*) (format t "      got:  ~a~%      want: ~a~%" got want))
    ok))

(defun hex->bytes (s)
  (let ((out (make-array (/ (length s) 2) :element-type '(unsigned-byte 8))))
    (dotimes (i (length out) out)
      (setf (aref out i) (parse-integer s :start (* 2 i) :end (+ 2 (* 2 i)) :radix 16)))))
(defun bytes->hex (b)
  (string-downcase (with-output-to-string (s) (loop for x across b do (format s "~2,'0x" x)))))
(defun ascii (s) (sha:ascii->bytes s))

(defun run-all ()
  (let ((*fail* 0))
    (secp:secp-init)
    (format t "~&== SHA-256 (FIPS 180-4 vectors) ==~%")
    (check "sha256(\"\")" (bytes->hex (sha:sha256 (ascii "")))
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    (check "sha256(\"abc\")" (bytes->hex (sha:sha256 (ascii "abc")))
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    (check "sha256(896-bit msg)"
           (bytes->hex (sha:sha256 (ascii "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")

    (format t "== HMAC-SHA256 (RFC 4231) ==~%")
    (check "hmac case 1"
           (bytes->hex (sha:hmac-sha256 (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x0b)
                                        (ascii "Hi There")))
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")

    (format t "== secp256k1 public keys ==~%")
    (check "1*G = generator x"
           (bytes->hex (secp:int-to-bytes32 (secp:secp-x (secp:secp-pubkey 1))))
           "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    (check "x-only pubkey of priv=3 (BIP340)"
           (string-upcase (bytes->hex (schnorr:pubkey-xonly 3)))
           "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    (check "pubkey on curve" (secp:secp-on-curve-p (secp:secp-pubkey 12345)) t)
    (check "n*G = infinity" (secp:secp-inf-p (secp:secp-mul-point secp:*secp256k1-n* (secp:secp-generator))) t)

    (format t "== ECDSA round-trips (RFC6979) ==~%")
    (dotimes (i 5)
      (let* ((priv (+ 1 (mod (* (1+ i) 2654435761) (1- secp:*secp256k1-n*))))
             (pub (secp:secp-pubkey priv))
             (h (sha:sha256 (ascii (format nil "ecdsa-msg-~d" i)))))
        (multiple-value-bind (r s) (secp:ecdsa-sign-raw priv h)
          (check (format nil "ecdsa verify #~d" i) (and (secp:ecdsa-verify pub h r s) t) t)
          (check (format nil "ecdsa reject tampered #~d" i) (secp:ecdsa-verify pub h r (1+ s)) nil))))

    (format t "== BIP340 Schnorr round-trips ==~%")
    (dotimes (i 5)
      (let* ((priv (+ 1 (mod (* (+ i 7) 40503) (1- secp:*secp256k1-n*))))
             (px (schnorr:pubkey-xonly priv))
             (m (sha:sha256 (ascii (format nil "schnorr-msg-~d" i))))
             (sig (schnorr:schnorr-sign priv m)))
        (check (format nil "schnorr verify #~d" i) (and (schnorr:schnorr-verify px m sig) t) t)
        (let ((bad (copy-seq sig)))
          (setf (aref bad 33) (logxor (aref bad 33) 1))
          (check (format nil "schnorr reject tampered #~d" i) (schnorr:schnorr-verify px m bad) nil))))

    #+(and sbcl (or x86-64 arm64))
    (progn
      (format t "== VOP limb field backend (~a) ==~%"
              #+x86-64 "x86-64" #+(and arm64 (not x86-64)) "arm64")
      (let ((p secp:*secp256k1-p*) (om (secp::mkfe)) (oa (secp::mkfe)) (os (secp::mkfe))
            (mok t) (aok t) (sok t))
        (dotimes (i 20000)
          (let* ((x (random p)) (y (random p)) (fx (secp::i->fe x)) (fy (secp::i->fe y)))
            (secp::fmul! om fx fy) (unless (= (secp::f->i om) (mod (* x y) p)) (setf mok nil))
            (secp::fadd! oa fx fy) (unless (= (secp::f->i oa) (mod (+ x y) p)) (setf aok nil))
            (secp::fsub! os fx fy) (unless (= (secp::f->i os) (mod (- x y) p)) (setf sok nil))))
        (check "%mul256+%reducep fmul! == (* a b) mod p (20k)" mok t)
        (check "%fadd == (+ a b) mod p (20k)" aok t)
        (check "%fsub == (- a b) mod p (20k)" sok t))
      ;; NOTE: every ECDSA/Schnorr/pubkey test above now runs through the limb
      ;; backend (secp-mul-point/secp-mul-2 are redefined on x86-64 and arm64),
      ;; so the whole suite is the per-architecture differential oracle for the
      ;; VOPs.  On x86-64 the MUL encoding is also byte-identical to modus's
      ;; verified encoder (cross-checked).
      )

    (format t "~%~a (~d failure~:p)~%" (if (zerop *fail*) "ALL PASS" "FAILURES") *fail*)
    (when (plusp *fail*) (error "secp256k1-fast: ~d test failure(s)" *fail*))
    t))

;;; Compare against cl-consensus's crypto over random inputs.
;;; NOTE: cl-consensus now DEPENDS ON secp256k1-fast (its crypto is a re-export
;;; shim), so this is a self-consistency smoke test, not an independent oracle.
;;; The real cross-implementation validation against Bitcoin Core is
;;; cl-consensus's regression (conformance / block sweep / libbitcoinkernel FFI
;;; diff), which now runs entirely on this crypto.
;;; Run manually:  (secp256k1-fast.test:cross-check 500)
(defun cross-check (&optional (rounds 500))
  (secp:secp-init)
  (handler-case (asdf:load-system "cl-consensus") (error () nil))
  (let ((ec (find-package :cl-consensus.crypto.secp256k1))
        (sc (find-package :cl-consensus.crypto.schnorr))
        (fails 0))
    (unless (and ec sc) (format t "cl-consensus not loadable; skipping cross-check~%") (return-from cross-check nil))
    (dotimes (i rounds)
      (let* ((priv (+ 1 (mod (* (+ i 1) 2654435761) (1- secp:*secp256k1-n*))))
             (h (sha:sha256 (ascii (format nil "x~d" i)))))
        ;; pubkey
        (let ((a (secp:int-to-bytes32 (secp:secp-x (secp:secp-pubkey priv))))
              (b (funcall (intern "INT-TO-BYTES32" ec)
                          (funcall (intern "SECP-X" ec) (funcall (intern "SECP-PUBKEY" ec) priv)))))
          (unless (equalp a b) (incf fails) (format t "pubkey mismatch ~d~%" i)))
        ;; ECDSA: deterministic, so signatures must be byte-identical
        (multiple-value-bind (r1 s1) (secp:ecdsa-sign-raw priv h)
          (multiple-value-bind (r2 s2) (funcall (intern "ECDSA-SIGN-RAW" ec) priv h)
            (unless (and (= r1 r2) (= s1 s2)) (incf fails) (format t "ecdsa mismatch ~d~%" i))))
        ;; Schnorr: deterministic, byte-identical signatures
        (let* ((m h)
               (sa (schnorr:schnorr-sign priv m))
               (sb (funcall (intern "SCHNORR-SIGN" sc) priv m)))
          (unless (equalp sa sb) (incf fails) (format t "schnorr mismatch ~d~%" i)))))
    (format t "~&cross-check vs cl-consensus (~d rounds): ~a~%"
            rounds (if (zerop fails) "IDENTICAL" (format nil "~d MISMATCH" fails)))
    (zerop fails)))

;;; Reproduce the README's per-core throughput numbers.
;;;   (secp256k1-fast.test:bench)
(defun bench (&optional (reps 4000))
  (secp:secp-init)
  (flet ((rate (thunk n) (let ((s (get-internal-run-time)))
                           (dotimes (i n) (funcall thunk))
                           (/ n (/ (float (- (get-internal-run-time) s)) internal-time-units-per-second)))))
    (let* ((priv 424242424242424242) (pub (secp:secp-pubkey priv))
           (h (sha:sha256 (ascii "bench")))
           (d 987654321987654321) (px (schnorr:pubkey-xonly d))
           (m (sha:sha256 (ascii "bench"))) (ssig (schnorr:schnorr-sign d m)))
      (multiple-value-bind (r s) (secp:ecdsa-sign-raw priv h)
        (format t "~&== secp256k1-fast throughput (per core) ==~%")
        (format t "  ECDSA verify   : ~,0f ops/s~%" (rate (lambda () (secp:ecdsa-verify pub h r s)) reps))
        (format t "  Schnorr verify : ~,0f ops/s~%" (rate (lambda () (schnorr:schnorr-verify px m ssig)) reps))
        (format t "  scalar mult kG : ~,0f ops/s~%" (rate (lambda () (secp:secp-mul-point priv (secp:secp-generator))) reps))
        (values)))))

;;; Multicore: verification is embarrassingly parallel.  Each worker thread wraps
;;; its loop in WITH-FRESH-SCRATCH (per-thread buffers); without it the shared
;;; scratch would corrupt across threads.  Run:  (secp256k1-fast.test:thread-test)
(defun thread-test (&optional (nthreads 16) (per 3000))
  (secp:secp-init)
  (let* ((priv 424242424242424242) (pub (secp:secp-pubkey priv)) (h (sha:sha256 (ascii "thr"))))
    (multiple-value-bind (r s) (secp:ecdsa-sign-raw priv h)
      (flet ((work ()                       ; per thread: `per` valid+tampered checks → error count
               (secp:with-fresh-scratch
                 (let ((bad 0))
                   (dotimes (i per)
                     (unless (secp:ecdsa-verify pub h r s) (incf bad))
                     (when (secp:ecdsa-verify pub h r (1+ s)) (incf bad)))
                   bad))))
        (let* ((rt0 (get-internal-real-time)) (b1 (work))
               (t1 (/ (float (- (get-internal-real-time) rt0)) internal-time-units-per-second))
               (rtn (get-internal-real-time))
               (threads (loop repeat nthreads collect (sb-thread:make-thread #'work)))
               (bads (mapcar #'sb-thread:join-thread threads))
               (tn (/ (float (- (get-internal-real-time) rtn)) internal-time-units-per-second))
               (errs (+ b1 (reduce #'+ bads))))
          (format t "~&== multicore verify: ~d threads ==~%" nthreads)
          (format t "  correctness   : ~a (~d errors / ~d concurrent verifies)~%"
                  (if (zerop errs) "OK" "FAIL") errs (* (1+ nthreads) per 2))
          (format t "  1 thread      : ~,0f verify/s~%" (/ (* per 2) t1))
          (format t "  ~d threads    : ~,0f verify/s aggregate (~,1fx)~%"
                  nthreads (/ (* nthreads per 2) tn) (/ (/ (* nthreads per 2) tn) (/ (* per 2) t1)))
          (zerop errs))))))
