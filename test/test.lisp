;;;; test/test.lisp — self-contained correctness tests.

(defpackage #:secp256k1-fast.test
  (:use #:cl)
  (:local-nicknames (#:secp #:secp256k1-fast) (#:schnorr #:secp256k1-fast.schnorr)
                    (#:sha #:secp256k1-fast.hash))
  (:export #:run-all #:cross-check #:bench #:thread-test #:ct-timing
           #:bench-mul-point #:ct-point-timing #:ct-mul-point-differential))

(in-package #:secp256k1-fast.test)

(defvar *fail* 0)
(defun check (name got want)
  (let ((ok (equalp got want)))
    (format t "  [~a] ~a~%" (if ok "PASS" "FAIL") name)
    (unless ok (incf *fail*) (format t "      got:  ~a~%      want: ~a~%" got want))
    ok))

(defun sk (n)
  "A fixed 32-byte private key from the PUBLIC test integer N (tests only)."
  (gossamer:pooled-copy (secp:int-to-bytes32 n)))

(defun ecdh (a point)
  "ECDH-X with the test integer A as the private key, into a fresh fixed buffer."
  (let ((out (gossamer:make-fixed-octets 32)))
    (secp256k1-fast.ecdh:ecdh-x (sk a) point out)
    (coerce out '(simple-array (unsigned-byte 8) (*)))))

(defparameter *bip340-vectors*
  '(;; BIP-340 vectors 15-18: messages that are not 32 bytes
    ("0340034003400340034003400340034003400340034003400340034003400340"
     "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
     "0000000000000000000000000000000000000000000000000000000000000000"
     ""
     "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63")
    ;; BIP-340 vectors 15-18: messages that are not 32 bytes
    ("0340034003400340034003400340034003400340034003400340034003400340"
     "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
     "0000000000000000000000000000000000000000000000000000000000000000"
     "11"
     "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF")
    ("0340034003400340034003400340034003400340034003400340034003400340"
     "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
     "0000000000000000000000000000000000000000000000000000000000000000"
     "0102030405060708090A0B0C0D0E0F1011"
     "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5")
    ("0340034003400340034003400340034003400340034003400340034003400340"
     "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117"
     "0000000000000000000000000000000000000000000000000000000000000000"
     "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"
     "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367")
    ("0000000000000000000000000000000000000000000000000000000000000003"
     "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
     "0000000000000000000000000000000000000000000000000000000000000000"
     "0000000000000000000000000000000000000000000000000000000000000000"
     "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
    ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
     "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
     "0000000000000000000000000000000000000000000000000000000000000001"
     "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
     "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A")
    ("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
     "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"
     "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"
     "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"
     "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7")
    ("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710"
     "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
     "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3")))

#+sbcl
(defun %heap-holds-p (patterns)
  "How many moving-heap objects contain any of PATTERNS (each a list of an element
type and a vector): octet vectors by subsequence, word/limb arrays by equality of
contents."
  (let ((hits 0))
    (sb-vm:map-allocated-objects
     (lambda (obj type size) (declare (ignore type size))
       (dolist (p patterns)
         (when (and (typep obj (car p)) (>= (length obj) (length (cdr p))) (search (cdr p) obj))
           (incf hits))))
     :dynamic)
    hits))

(defun residue-check ()
  "After signing with a fixed key and a full GC, no moving-heap object holds the key
as bytes, as 64-bit limbs, as 32-bit words or as its nibbles -- and the scan does see
those shapes when the old integer path is used (positive control)."
  #-sbcl (format t "  (residue check is SBCL-only)~%")
  #+sbcl
  (let* ((d #x8E3F15F4A7B1C2D30E4F5A6B7C8D9EA1B2C3D4E5F60718293A4B5C6D7E8F9012)
         (key (sk d))
         (bytes (coerce (secp:int-to-bytes32 d) '(simple-array (unsigned-byte 8) (*))))
         (limbs (let ((v (make-array 4 :element-type '(unsigned-byte 64))))
                  (dotimes (i 4 v) (setf (aref v i) (ldb (byte 64 (* 64 i)) d)))))
         (words (let ((v (make-array 8 :element-type 'fixnum)))
                  (dotimes (i 8 v) (setf (aref v i) (ldb (byte 32 (* 32 i)) d)))))
         (nibs (let ((v (make-array 64 :element-type 'fixnum)))
                 (dotimes (i 64 v) (setf (aref v i) (ldb (byte 4 (* 4 i)) d)))))
         (pats (list (cons '(simple-array (unsigned-byte 8) (*)) bytes)
                     (cons '(simple-array (unsigned-byte 64) (*)) limbs)
                     (cons '(simple-array fixnum (*)) words)
                     (cons '(simple-array fixnum (*)) nibs)))
         (m (sha:sha256 (ascii "residue"))))
    (sb-ext:gc :full t)
    (let ((base (%heap-holds-p pats)))
      ;; Every operation takes the FIXED key.  (The ECDH helper above takes an integer
      ;; and builds the key's bytes on the heap to import them -- a copy the test makes,
      ;; which a stale stack slot can keep alive through the GC on arm64.)
      (let ((shared (gossamer:make-fixed-octets 32)))
        (dotimes (i 20)
          (schnorr:schnorr-sign key m) (secp:ecdsa-sign-raw key m) (schnorr:pubkey-xonly key)
          (secp256k1-fast.ecdh:ecdh-x key (secp:secp-generator) shared)))
      (sb-ext:gc :full t)
      (let ((after (%heap-holds-p pats)))
        (format t "  key-shaped heap objects: ~a baseline (the patterns), ~a after 80 secret operations~%" base after)
        (check "no key bytes, limbs, words or nibbles left on the moving heap" (- after base) 0))
      ;; positive control: the integer ladder conses the key's limbs and nibbles
      (secp:ct-mul-g d)
      (check "residue scan sees the integer path's copies" (> (%heap-holds-p pats) base) t))))

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
           (bytes->hex (secp:int-to-bytes32 (secp:secp-x (secp:secp-pubkey (sk 1)))))
           "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    (check "x-only pubkey of priv=3 (BIP340)"
           (string-upcase (bytes->hex (schnorr:pubkey-xonly (sk 3))))
           "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    (check "pubkey on curve" (secp:secp-on-curve-p (secp:secp-pubkey (sk 12345))) t)
    (check "n*G = infinity" (secp:secp-inf-p (secp:secp-mul-point secp:*secp256k1-n* (secp:secp-generator))) t)

    (format t "== FIPS ECDH (secp256k1-fast.ecdh) ==~%")
    ;; 3 * (5G) = 15G; its x computed independently with python-ecdsa
    (check "ecdh-x 3 (5G) = x(15G), independent value"
           (bytes->hex (ecdh 3 (secp:secp-pubkey (sk 5))))
           "d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e")
    (let ((a 987654321987) (b 123456789123456789))
      (check "ecdh-x is symmetric: a*(bG) = b*(aG)"
             (ecdh a (secp:secp-pubkey (sk b)))
             (ecdh b (secp:secp-pubkey (sk a)))))
    (flet ((refused (pt)
             (handler-case (progn (ecdh 5 pt) nil) (error () t))))
      (check "ecdh-x refuses an off-curve point (1 . 1)" (refused (cons 1 1)) t)
      (check "ecdh-x refuses the point at infinity" (refused (secp:secp-mul-point secp:*secp256k1-n* (secp:secp-generator))) t)
      (let ((g (secp:secp-generator)))
        (check "ecdh-x refuses x >= p (same residue as G's x)"
               (refused (cons (+ (car g) secp:*secp256k1-p*) (cdr g))) t)
        (check "ecdh-x accepts the generator" (refused g) nil)))

    (format t "== ECDSA round-trips (RFC6979) ==~%")
    (dotimes (i 5)
      (let* ((priv (+ 1 (mod (* (1+ i) 2654435761) (1- secp:*secp256k1-n*))))
             (pub (secp:secp-pubkey (sk priv)))
             (h (sha:sha256 (ascii (format nil "ecdsa-msg-~d" i)))))
        (multiple-value-bind (r s) (secp:ecdsa-sign-raw (sk priv) h)
          (check (format nil "ecdsa verify #~d" i) (and (secp:ecdsa-verify pub h r s) t) t)
          (check (format nil "ecdsa reject tampered #~d" i) (secp:ecdsa-verify pub h r (1+ s)) nil))))

    (format t "== BIP340 Schnorr round-trips ==~%")
    (dotimes (i 5)
      (let* ((priv (+ 1 (mod (* (+ i 7) 40503) (1- secp:*secp256k1-n*))))
             (px (schnorr:pubkey-xonly (sk priv)))
             (m (sha:sha256 (ascii (format nil "schnorr-msg-~d" i))))
             (sig (schnorr:schnorr-sign (sk priv) m)))
        (check (format nil "schnorr verify #~d" i) (and (schnorr:schnorr-verify px m sig) t) t)
        (let ((bad (copy-seq sig)))
          (setf (aref bad 33) (logxor (aref bad 33) 1))
          (check (format nil "schnorr reject tampered #~d" i) (schnorr:schnorr-verify px m bad) nil))))

    #+(or (and sbcl (or x86-64 arm64)) modus-mul-split)
    (progn
      (format t "== limb field backend (~a) ==~%"
              #+modus-mul-split "modus 5x52, %mul-split"
              #+(and sbcl x86-64) "x86-64 VOPs" #+(and sbcl arm64 (not x86-64)) "arm64 VOPs")
      (let ((p secp:*secp256k1-p*) (om (secp::mkfe)) (oa (secp::mkfe)) (os (secp::mkfe))
            (mok t) (aok t) (sok t))
        (dotimes (i 20000)
          (let* ((x (random p)) (y (random p)) (fx (secp::i->fe x)) (fy (secp::i->fe y)))
            (secp::fmul! om fx fy) (unless (= (secp::f->i om) (mod (* x y) p)) (setf mok nil))
            (secp::fadd! oa fx fy) (unless (= (secp::f->i oa) (mod (+ x y) p)) (setf aok nil))
            (secp::fsub! os fx fy) (unless (= (secp::f->i os) (mod (- x y) p)) (setf sok nil))))
        (check "fmul! == (* a b) mod p (20k)" mok t)
        (check "fadd! == (+ a b) mod p (20k)" aok t)
        (check "fsub! == (- a b) mod p (20k)" sok t))
      ;; Chained: each op's OUTPUT is the next op's input, never re-canonicalized,
      ;; so a backend that keeps elements only weakly reduced (modus's 5x52) is
      ;; exercised on its own outputs, not just on fresh I->FE values.
      (let* ((p secp:*secp256k1-p*) (vals (make-array 8)) (fes (make-array 8)) (ok t))
        (dotimes (i 8)
          (let ((x (random p))) (setf (aref vals i) x (aref fes i) (secp::i->fe x))))
        (dotimes (step 30000)
          (let* ((d (random 8)) (a (random 8)) (b (random 8)) (op (random 5))
                 (fa (aref fes a)) (fb (aref fes b)) (out (secp::mkfe))
                 (va (aref vals a)) (vb (aref vals b)))
            (ecase op
              (0 (secp::fmul! out fa fb) (setf (aref vals d) (mod (* va vb) p)))
              (1 (secp::fsqr! out fa) (setf (aref vals d) (mod (* va va) p)))
              (2 (secp::fadd! out fa fb) (setf (aref vals d) (mod (+ va vb) p)))
              (3 (secp::fsub! out fa fb) (setf (aref vals d) (mod (- va vb) p)))
              (4 (secp::fdbl! out fa) (setf (aref vals d) (mod (* 2 va) p))))
            (setf (aref fes d) out)
            (unless (= (secp::f->i out) (aref vals d)) (setf ok nil))
            (unless (eq (secp::fzero? out) (zerop (aref vals d))) (setf ok nil))))
        (check "chained field ops on their own outputs == integer oracle (30k)" ok t))
      ;; Values a weakly reduced element can hold that a canonical one cannot.
      #+modus-mul-split
      (let* ((p secp:*secp256k1-p*) (ok t)
             (top (vector #xFFFFFFFFFFFFF #xFFFFFFFFFFFFF #xFFFFFFFFFFFFF #xFFFFFFFFFFFFF
                          #x1000000000000))   ; the largest weak element, 2^256+2^208-1
             (topv (+ (ash 1 256) (ash 1 208) -1)))
        (dolist (x (list 0 1 (1- p) p (1+ p) (- (ash 1 256) 1) (random p)))
          (let ((fx (secp::i->fe x)) (o (secp::mkfe)))
            (secp::fmul! o fx top) (unless (= (secp::f->i o) (mod (* x topv) p)) (setf ok nil))
            (secp::fmul! o top top) (unless (= (secp::f->i o) (mod (* topv topv) p)) (setf ok nil))
            (secp::fsub! o fx top) (unless (= (secp::f->i o) (mod (- x topv) p)) (setf ok nil))
            (secp::fsub! o top fx) (unless (= (secp::f->i o) (mod (- topv x) p)) (setf ok nil))
            (secp::fadd! o top top) (unless (= (secp::f->i o) (mod (* 2 topv) p)) (setf ok nil))
            (unless (eq (secp::fzero? fx) (zerop (mod x p))) (setf ok nil))))
        (check "field ops at the weak-form limits (incl. p, 2^256-1, 2^256+2^208-1)" ok t))
      ;; The Montgomery product mod n itself, through CT-NMUL (a*b mod n).
      (let ((n secp:*secp256k1-n*) (ok t))
        (dolist (pair (list* (cons 0 0) (cons 1 1) (cons (1- n) (1- n)) (cons (1- n) 1)
                             (loop repeat 5000 collect (cons (random n) (random n)))))
          (unless (= (secp:ct-nmul (car pair) (cdr pair)) (mod (* (car pair) (cdr pair)) n))
            (setf ok nil)))
        (check "ct-nmul (Montgomery mod n) == (* a b) mod n (5k + edges)" ok t))
      ;; The square-root addition chain against the bignum exponentiation it
      ;; replaces, on squares and non-squares alike (the chain is the same
      ;; exponent either way; LIFT-X / DECODE-PUBKEY check the square after).
      (let* ((p secp:*secp256k1-p*) (e (floor (+ p 1) 4)) (ok t))
        (dolist (c (list* 0 1 4 7 (1- p) (loop repeat 2000 collect (random p))))
          (unless (= (secp:secp-sqrt-candidate c) (secp:mod-expt c e p)) (setf ok nil)))
        (check "secp-sqrt-candidate (limb chain) == c^((p+1)/4) mod p (2k + edges)" ok t))
      ;; Direct differential check of the scalar-field VOP path: secp-inv-mod with
      ;; m=n runs the Montgomery inverse (%mul256 + %montredn) — the one VOP not
      ;; covered by the F_p loop above.  Oracle is mod-expt a^(n-2) (portable
      ;; bignum, independent of the VOPs); also assert a·a⁻¹ ≡ 1 (mod n).
      (let ((n secp:*secp256k1-n*) (niok t))
        (dotimes (i 5000)
          (let* ((a (+ 1 (random (1- n))))
                 (got (secp:secp-inv-mod a n)))
            (unless (and (= got (secp:mod-expt a (- n 2) n)) (= 1 (mod (* a got) n)))
              (setf niok nil))))
        (check "Montgomery n-inverse == a^(n-2) mod n (5k)" niok t))
      ;; NOTE: every ECDSA/Schnorr/pubkey test above now runs through the limb
      ;; backend (secp-mul-point/secp-mul-2 are redefined on x86-64 and arm64),
      ;; so the whole suite is the per-architecture differential oracle for the
      ;; VOPs.  On x86-64 the MUL encoding is also byte-identical to modus's
      ;; verified encoder (cross-checked).
      )

    (format t "~%== constant-time k*G (vs variable-time path) ==~%")
    (check "ct-mul-g available on this backend" (secp:ct-mul-g-available-p) t)
    (let ((n secp:*secp256k1-n*) (ok t))
      (dolist (k (list* 1 2 15 16 17 255 256 (1- n) (ash n -1)
                        (loop repeat 64 collect (1+ (random (1- n))))))
        (let ((a (secp:secp-mul-point k (secp:secp-generator)))
              (b (secp:ct-mul-g k)))
          (unless (if (secp:secp-inf-p a) (secp:secp-inf-p b)
                      (and (not (secp:secp-inf-p b))
                           (= (secp:secp-x a) (secp:secp-x b))
                           (= (secp:secp-y a) (secp:secp-y b))))
            (setf ok nil))))
      (check "ct-mul-g == secp-mul-point (edge cases + 64 random)" ok t))

    ;; Constant-time property (deterministic): ct-mul-g must perform the SAME
    ;; number of point operations for every scalar.  We count the non-inlined
    ;; ct-cadd! / %ct-select calls (the field ops below them are inlined, and
    ;; fixed-count per call) across wildly different scalars; the variable-time
    ;; path is shown alongside to vary.
    (when (secp:ct-mul-g-available-p)
      (let ((n secp:*secp256k1-n*)
            (o-cadd (symbol-function 'secp::ct-cadd!))
            (o-sel  (symbol-function 'secp::%ct-select))
            (o-jadd (symbol-function 'secp::jadd!))
            (o-jdbl (symbol-function 'secp::jdbl!))
            (cadd 0) (sel 0) (jpt 0) (ct-profiles '()) (vt-counts '()))
        (secp:ct-mul-g 7)               ; warm the precomputed table
        (setf (symbol-function 'secp::ct-cadd!) (lambda (&rest a) (incf cadd) (apply o-cadd a))
              (symbol-function 'secp::%ct-select) (lambda (&rest a) (incf sel) (apply o-sel a))
              (symbol-function 'secp::jadd!) (lambda (&rest a) (incf jpt) (apply o-jadd a))
              (symbol-function 'secp::jdbl!) (lambda (&rest a) (incf jpt) (apply o-jdbl a)))
        (unwind-protect
             (dolist (k (list 1 (1- n) (ash 1 255) (1+ (random n)) (1+ (random n)) (1+ (random n))))
               (setf cadd 0 sel 0) (secp:ct-mul-g k) (pushnew (cons cadd sel) ct-profiles :test #'equal)
               (setf jpt 0) (secp:secp-mul-point k (secp:secp-generator)) (pushnew jpt vt-counts))
          (setf (symbol-function 'secp::ct-cadd!) o-cadd (symbol-function 'secp::%ct-select) o-sel
                (symbol-function 'secp::jadd!) o-jadd (symbol-function 'secp::jdbl!) o-jdbl))
        (format t "  (ct-mul-g point-op profile: ~a;  variable-time counts: ~a)~%"
                ct-profiles (sort (copy-list vt-counts) #'<))
        (check "ct-mul-g op-count is scalar-independent" (length ct-profiles) 1)
        (check "variable-time path op-count DOES vary (sanity)" (> (length vt-counts) 1) t)))

    (format t "~%== constant-time variable-base k*P (vs variable-time path) ==~%")
    (check "ct-mul-point available on this backend" (secp:ct-mul-point-available-p)
           #+(or (and sbcl (or x86-64 arm64)) modus-mul-split) t
           #-(or (and sbcl (or x86-64 arm64)) modus-mul-split) nil)
    (ct-mul-point-differential 2000)
    (when (secp:ct-mul-point-available-p)
      (let ((n secp:*secp256k1-n*)
            (o-cadd (symbol-function 'secp::ct-cadd!))
            (o-sel  (symbol-function 'secp::%ct-select-tab))
            (p (secp:secp-mul-point 987654321 (secp:secp-generator)))
            (cadd 0) (sel 0) (profiles '()))
        (setf (symbol-function 'secp::ct-cadd!) (lambda (&rest a) (incf cadd) (apply o-cadd a))
              (symbol-function 'secp::%ct-select-tab) (lambda (&rest a) (incf sel) (apply o-sel a)))
        (unwind-protect
             (dolist (k (list 0 1 15 16 (1- n) n (1+ n) (ash 1 255) (1- (ash 1 256))
                              (1+ (random n)) (1+ (random n))))
               (setf cadd 0 sel 0) (secp:ct-mul-point k p)
               (pushnew (cons cadd sel) profiles :test #'equal))
          (setf (symbol-function 'secp::ct-cadd!) o-cadd
                (symbol-function 'secp::%ct-select-tab) o-sel))
        (format t "  (ct-mul-point point-op profile (cadd . select): ~a)~%" profiles)
        (check "ct-mul-point op-count is scalar-independent" (length profiles) 1)))

    (format t "~%== BIP-340 signing vectors (bip-0340/test-vectors.csv, 0-3) ==~%")
    (loop for (seck pub aux msg sig) in *bip340-vectors* for i from 0 do
      (let ((sk (gossamer:fixed-copy (hex->bytes seck))))
        (check (format nil "bip340 #~a pubkey" i) (string-upcase (bytes->hex (schnorr:pubkey-xonly sk))) pub)
        (check (format nil "bip340 #~a signature" i)
               (string-upcase (bytes->hex (schnorr:schnorr-sign sk (hex->bytes msg) (hex->bytes aux)))) sig)))

    (format t "~%== RFC 6979 / ECDSA (secp256k1, key 1, \"Satoshi Nakamoto\") ==~%")
    (let ((sk (sk 1)) (h (sha:sha256 (ascii "Satoshi Nakamoto"))))
      (check "rfc6979 k" (format nil "~(~64,'0x~)" (secp:rfc6979-k sk h))
             "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15")
      (multiple-value-bind (r s) (secp:ecdsa-sign-raw sk h)
        (check "ecdsa r" (format nil "~(~64,'0x~)" r) "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8")
        (check "ecdsa s (low-s)" (format nil "~(~64,'0x~)" s) "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5")))

    (format t "~%== secret discipline ==~%")
    (check "an integer private key is refused"
           (handler-case (progn (schnorr:schnorr-sign 3 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)) :accepted)
             (error () :refused))
           :refused)
    (check "a heap copy of a private key is refused"
           (handler-case (progn (schnorr:pubkey-xonly (secp:int-to-bytes32 3)) :accepted) (gossamer:not-fixed () :refused))
           :refused)
    (check "a key >= n is refused"
           (handler-case (progn (schnorr:pubkey-xonly (gossamer:fixed-copy (secp:int-to-bytes32 secp:*secp256k1-n*))) :accepted)
             (error () :refused))
           :refused)
    (format t "~%== key arithmetic on fixed buffers ==~%")
    (let ((n secp:*secp256k1-n*) (state (sb-ext:seed-random-state 7)) (ok t))
      (dotimes (i 50)
        (let* ((a (1+ (random (1- n) state))) (b (1+ (random (1- n) state)))
               (out (gossamer:make-fixed-octets 32)) (out33 (gossamer:make-fixed-octets 33))
               (g (secp:secp-generator)))
          (flet ((int (buf) (secp:bytes-to-int buf)))
            (secp:seckey-negate-into (sk a) out)
            (unless (= (int out) (- n a)) (setf ok nil))
            (secp:seckey-negate-into (sk a) out :negate nil)
            (unless (= (int out) a) (setf ok nil))
            (secp:seckey-tweak-mul-into (sk a) (sk b) out)
            (unless (= (int out) (mod (* a b) n)) (setf ok nil))
            (secp:seckey-add-into (sk a) (sk b) out)
            (unless (= (int out) (mod (+ a b) n)) (setf ok nil))
            (let ((pt (secp:secp-mul-point a (secp:secp-mul-point b g))))
              (secp256k1-fast.ecdh:ecdh-compressed-into (sk a) (secp:secp-mul-point b g) out33)
              (unless (and (= (aref out33 0) (if (oddp (secp:secp-y pt)) 3 2))
                           (= (secp:bytes-to-int (subseq out33 1)) (secp:secp-x pt)))
                (setf ok nil))))))
      (check "negate / tweak-mul / add / compressed ECDH agree with integer math (50 random)" ok t))
    (check "tweak-mul refuses a zero tweak"
           (handler-case (progn (secp:seckey-tweak-mul-into (sk 5) (gossamer:fixed-copy (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                                                            (gossamer:make-fixed-octets 32)) :accepted)
             (error () :refused))
           :refused)
    (residue-check)

    (format t "~%== thread safety (concurrent key derivation) ==~%")
    (thread-safety)

    (format t "~%~a (~d failure~:p)~%" (if (zerop *fail*) "ALL PASS" "FAILURES") *fail*)
    (when (plusp *fail*) (error "secp256k1-fast: ~d test failure(s)" *fail*))
    t))

(defun same-point-p (a b)
  (if (secp:secp-inf-p a)
      (secp:secp-inf-p b)
      (and (not (secp:secp-inf-p b))
           (= (secp:secp-x a) (secp:secp-x b))
           (= (secp:secp-y a) (secp:secp-y b)))))

(defun ct-mul-point-differential (&optional (rounds 2000))
  "CT-MUL-POINT must equal SECP-MUL-POINT for every (scalar, point): ROUNDS
random pairs plus the edge scalars (0, 1, n-1, n, n+1, multiples of n, 2^256-1,
values just past 2^256) against random points, G, and the point at infinity."
  (secp:secp-init)
  (let* ((n secp:*secp256k1-n*) (g (secp:secp-generator)) (inf secp::*secp256k1-infinity*)
         (edge-k (list 0 1 2 15 16 17 (1- n) n (1+ n) (* 2 n) (1+ (* 2 n)) (* 5 n) (* 1000 n)
                       (ash n -1) (1- (ash 1 256)) (ash 1 256) (+ (ash 1 256) 7)
                       (ash 1 255) (- (ash 1 256) n) (- (ash 1 256) n 1) -1 (- n)))
         (pts (list* g inf (secp:secp-mul-point (1- n) g)       ; -G
                     (loop repeat 6 collect (secp:secp-mul-point (1+ (random (1- n))) g))))
         (bad 0) (total 0))
    (flet ((one (k p)
             (incf total)
             (unless (same-point-p (secp:ct-mul-point k p) (secp:secp-mul-point k p))
               (incf bad)
               (when (<= bad 5) (format t "      mismatch k=~x p=~a~%" k p)))))
      (dolist (k edge-k) (dolist (p pts) (one k p)))
      (dotimes (i rounds)
        (one (if (zerop (mod i 4)) (random (ash 1 256)) (random n))
             (if (zerop (mod i 97)) inf (secp:secp-mul-point (1+ (random (1- n))) g)))))
    (check (format nil "ct-mul-point == secp-mul-point (~d pairs: ~d random + edge scalars x points incl. infinity)"
                   total rounds)
           bad 0)))

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
        (let ((a (secp:int-to-bytes32 (secp:secp-x (secp:secp-pubkey (sk priv)))))
              (b (funcall (intern "INT-TO-BYTES32" ec)
                          (funcall (intern "SECP-X" ec) (funcall (intern "SECP-PUBKEY" ec) priv)))))
          (unless (equalp a b) (incf fails) (format t "pubkey mismatch ~d~%" i)))
        ;; ECDSA: deterministic, so signatures must be byte-identical
        (multiple-value-bind (r1 s1) (secp:ecdsa-sign-raw (sk priv) h)
          (multiple-value-bind (r2 s2) (funcall (intern "ECDSA-SIGN-RAW" ec) priv h)
            (unless (and (= r1 r2) (= s1 s2)) (incf fails) (format t "ecdsa mismatch ~d~%" i))))
        ;; Schnorr: deterministic, byte-identical signatures
        (let* ((m h)
               (sa (schnorr:schnorr-sign (sk priv) m))
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
    (let* ((priv 424242424242424242) (pub (secp:secp-pubkey (sk priv)))
           (h (sha:sha256 (ascii "bench")))
           (d 987654321987654321) (px (schnorr:pubkey-xonly (sk d)))
           (m (sha:sha256 (ascii "bench"))) (ssig (schnorr:schnorr-sign (sk d) m)))
      (multiple-value-bind (r s) (secp:ecdsa-sign-raw (sk priv) h)
        (format t "~&== secp256k1-fast throughput (per core) ==~%")
        (format t "  ECDSA verify   : ~,0f ops/s~%" (rate (lambda () (secp:ecdsa-verify pub h r s)) reps))
        (format t "  Schnorr verify : ~,0f ops/s~%" (rate (lambda () (schnorr:schnorr-verify px m ssig)) reps))
        (format t "  scalar mult kG : ~,0f ops/s~%" (rate (lambda () (secp:secp-mul-point priv (secp:secp-generator))) reps))
        (values)))))

;;; Variable-base k*P with a full-size secret-like scalar (the ECDH shape):
;;; the existing variable-time SECP-MUL-POINT against the constant-time
;;; CT-MUL-POINT.  Kept separate from BENCH so BENCH's rates are unchanged.
;;;   (secp256k1-fast.test:bench-mul-point)
(defun bench-mul-point (&optional (reps 2000))
  (secp:secp-init)
  (flet ((rate (thunk n) (let ((s (get-internal-run-time)))
                           (dotimes (i n) (funcall thunk))
                           (/ n (/ (float (- (get-internal-run-time) s)) internal-time-units-per-second)))))
    (let* ((k #xC0FFEE1234567890ABCDEF00112233445566778899AABBCCDDEEFF0102030405)
           (p (secp:secp-mul-point #x1F2E3D4C5B6A79881726354453627180 (secp:secp-generator)))
           (vt (rate (lambda () (secp:secp-mul-point k p)) reps))
           (ct (rate (lambda () (secp:ct-mul-point k p)) reps)))
      (format t "~&== variable-base k*P (256-bit k, per core) ==~%")
      (format t "  secp-mul-point (variable-time) : ~,0f ops/s~%" vt)
      (format t "  ct-mul-point   (constant-time) : ~,0f ops/s  (~,2fx slower)~%" ct (/ vt ct))
      (values vt ct))))

(defun ct-point-timing (&optional (iters 400))
  "Mean wall ms per CT-MUL-POINT call for scalars of very different Hamming
weight / magnitude.  Should be flat; SBCL timing on a shared host is noisy and
is NOT a proof — the op-count check in RUN-ALL is the hard test."
  (secp:secp-init)
  (let* ((n secp:*secp256k1-n*)
         (p (secp:secp-mul-point 77777777777 (secp:secp-generator)))
         (classes (list (cons "k=1" 1) (cons "k=2^255" (ash 1 255)) (cons "k=n-1" (1- n))
                        (cons "low HW" #x8000000000000000000000000000000100000000000000000000000000000001)
                        (cons "high HW" (- n 2)) (cons "random" (1+ (random n))))))
    (secp:ct-mul-point 3 p)
    (format t "~&~10a | ct-mul-point ms | secp-mul-point ms~%" "scalar")
    (dolist (c classes)
      (flet ((ms (fn)
               (let ((t0 (get-internal-real-time)))
                 (dotimes (i iters) (funcall fn (cdr c) p))
                 (/ (* 1000.0 (- (get-internal-real-time) t0)) internal-time-units-per-second iters))))
        (format t "~10a |     ~7,4f     |     ~7,4f~%" (car c)
                (ms #'secp:ct-mul-point) (ms #'secp:secp-mul-point))))))

;;; Multicore: verification is embarrassingly parallel.  Each worker thread wraps
;;; its loop in WITH-FRESH-SCRATCH (per-thread buffers); without it the shared
;;; scratch would corrupt across threads.  Run:  (secp256k1-fast.test:thread-test)
(defun thread-test (&optional (nthreads 16) (per 3000))
  (secp:secp-init)
  (let* ((priv 424242424242424242) (pub (secp:secp-pubkey (sk priv))) (h (sha:sha256 (ascii "thr"))))
    (multiple-value-bind (r s) (secp:ecdsa-sign-raw (sk priv) h)
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

(defun thread-safety (&optional (threads 8) (iters 150))
  "Concurrent CT-MUL-G must agree with the single-threaded answer.

   The scratch in CT.LISP is module-level, so without WITH-FRESH-CT-SCRATCH
   concurrent callers overwrite each other's intermediates and the result comes
   back as the point at infinity or a valid-looking WRONG point — silent key
   corruption, which is about the worst failure mode this library has.  Every
   caller that derives public keys or signs from more than one thread depends on
   this, so it is a hard check and not a benchmark.

   Uses SB-THREAD directly: the system has no dependencies and this test is not
   going to be what introduces one."
  #-sb-thread (progn (format t "~&(no threads in this build — skipped)~%") t)
  #+sb-thread
  (let* ((k #x1111111111111111111111111111111111111111111111111111111111111111)
         (want (secp:secp-pubkey (sk k)))
         (bad 0)
         (lock (sb-thread:make-mutex)))
    (mapc #'sb-thread:join-thread
          (loop repeat threads
                collect (sb-thread:make-thread
                         (lambda ()
                           (secp:with-fresh-ct-scratch
                             (dotimes (i iters)
                               (let ((got (handler-case (secp:secp-pubkey (sk k))
                                            (error () nil))))
                                 (unless (equal got want)
                                   (sb-thread:with-mutex (lock) (incf bad))))))))))
    (check "concurrent ct-mul-g agrees with single-threaded"
           (format nil "~d wrong" bad) "0 wrong"))
  ;; The affine entry points share the limb backend's scratch through SECP-INV.
  ;; A taproot tweak (lift_x, then P + t*G) computed on one thread while another
  ;; verified signatures came out as a valid-looking wrong point (cl-deposits).
  ;; No WITH-FRESH-CT-SCRATCH here on purpose: the entry points must protect themselves.
  (let* ((x (secp:secp-x (secp:secp-pubkey (sk #x2222222222222222222222222222222222222222222222222222222222222222))))
         (p (secp256k1-fast.schnorr:lift-x x))
         (tg (secp:secp-pubkey (sk #x3333)))
         (want (secp:secp-add-points p tg))
         (bad 0)
         (lock (sb-thread:make-mutex)))
    (mapc #'sb-thread:join-thread
          (loop repeat threads
                collect (sb-thread:make-thread
                         (lambda ()
                           (dotimes (i iters)
                             (unless (and (equal (secp256k1-fast.schnorr:lift-x x) p)
                                          (equal (secp:secp-add-points p tg) want))
                               (sb-thread:with-mutex (lock) (incf bad))))))))
    (check "concurrent lift-x and affine add agree with single-threaded (unwrapped callers)"
           (format nil "~d wrong" bad) "0 wrong")))

(defun ct-timing (&optional (ct-iters 800) (vt-iters 20000))
  "Empirical timing: per-call ms for k*G across scalar classes.  The constant-
time path should be flat; the variable-time path tracks the scalar.  (Wall-clock
on a shared host is noisy — the op-count check in RUN-ALL is the hard test.)"
  (secp:secp-init)
  (secp:ct-mul-g 7)
  (let* ((n secp:*secp256k1-n*) (g (secp:secp-generator))
         (classes (list (cons "k=1" 1) (cons "k=n-1" (1- n)) (cons "k=2^255" (ash 1 255))
                        (cons "random" (1+ (random n))) (cons "random2" (1+ (random n))))))
    (flet ((ms (fn k iters)
             (let ((t0 (get-internal-real-time)))
               (dotimes (i iters) (funcall fn k))
               (/ (* 1000.0 (- (get-internal-real-time) t0)) internal-time-units-per-second iters))))
      (format t "~&~14a | ct-mul-g ms | var-time ms~%" "scalar class")
      (dolist (c classes)
        (format t "~14a |   ~6,4f    |   ~7,5f~%" (car c)
                (ms (lambda (k) (secp:ct-mul-g k)) (cdr c) ct-iters)
                (ms (lambda (k) (secp:secp-mul-point k g)) (cdr c) vt-iters))))))
