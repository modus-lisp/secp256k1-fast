;;;; src/threadsafe.lisp — the public entry points bind their own scratch.
;;;;
;;;; The limb backend keeps its working buffers in module-level specials for
;;;; speed.  WITH-FRESH-SCRATCH and WITH-FRESH-CT-SCRATCH rebind them per
;;;; thread — but until now only a caller who KNEW to wrap got that protection,
;;;; and a caller who forgot got results that were wrong in a way nothing
;;;; flagged: the point at infinity, or a valid-looking point that is not the
;;;; one asked for.  cl-payments hit exactly that the first time two of its
;;;; daemons ran in one process and derived keys on several threads at once.
;;;;
;;;; So the entry points wrap themselves.  Loaded last, this file replaces each
;;;; one with a version that binds fresh scratch around the original.  Nested
;;;; binding (a wrapped caller calling a wrapped callee) costs a few allocations
;;;; and is otherwise harmless; NOT binding costs correctness.  The macros stay
;;;; exported for callers who want one binding around a long batch instead of
;;;; one per call.

(in-package #:secp256k1-fast)

(defmacro %self-protecting (name lambda-list)
  "Replace NAME's definition with one that binds fresh scratch around it."
  (let ((inner (gensym "INNER")))
    `(let ((,inner (fdefinition ',name)))
       (setf (fdefinition ',name)
             (lambda ,lambda-list
               (with-fresh-ct-scratch (funcall ,inner ,@lambda-list)))))))

(%self-protecting secp-mul-point (k p))
(%self-protecting ct-mul-g (k))
(%self-protecting secp-pubkey (privkey))
(%self-protecting secp-inv-mod (a m))
(%self-protecting ecdsa-sign-raw (privkey-int hash-bytes))
(%self-protecting ecdsa-verify (pubkey-pt hash-bytes r s))
