;;;; secp256k1-fast.asd

(defsystem "secp256k1-fast"
  :description "Fast, dependency-free secp256k1 in Common Lisp: ECDSA (RFC6979) +
                BIP340 Schnorr, with Jacobian + Shamir scalar multiplication.  The
                field layer is a portable integer reference today; it's factored so
                an SBCL-VOP / MVM-native limb backend can slot in behind it later,
                with the reference kept as the differential oracle.  No external
                dependencies — its own SHA-256 / HMAC."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ()
  :serial t
  :components
  ((:module "src"
    :serial t
    :components ((:file "packages")
                 (:file "sha256")
                 (:file "hmac")
                 (:file "field")
                 (:file "scalar")
                 (:file "point")
                 (:file "ecdsa")
                 (:file "schnorr")
                 ;; Inline-asm field + limb scalar-mult backend (SBCL VOPs).
                 ;; The per-architecture VOP file comes FIRST (the VOPs must be
                 ;; registered before their callers compile), then field-limb.lisp
                 ;; — the architecture-neutral backend that calls those VOPs and
                 ;; redefines secp-mul-point / secp-mul-2 to run on limb arrays.
                 ;; Each arch supplies the same five VOPs (%mul256 %reducep %fadd
                 ;; %fsub %montredn); field-limb.lisp names only those symbols.
                 ;; Portable field.lisp / point.lisp stay as the fallback +
                 ;; differential oracle (and validate the VOPs on every arch).
                 (:file "field-vops-x86-64"  :if-feature (:and :sbcl :x86-64))
                 (:file "field-vops-aarch64" :if-feature (:and :sbcl :arm64))
                 (:file "field-limb" :if-feature (:and :sbcl (:or :x86-64 :arm64))))))
  :in-order-to ((test-op (test-op "secp256k1-fast/test"))))

(defsystem "secp256k1-fast/test"
  :description "Self-contained correctness tests: SHA-256/HMAC vectors, BIP340
                Schnorr vectors, ECDSA round-trips, field/curve laws."
  :depends-on ("secp256k1-fast")
  :serial t
  :components ((:module "test" :components ((:file "test"))))
  :perform (test-op (o c) (uiop:symbol-call '#:secp256k1-fast.test '#:run-all)))
