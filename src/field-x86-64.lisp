;;;; field-x86-64.lisp — x86-64 inline assembly for the field hot path, via SBCL
;;;; VOPs.  Loaded ONLY on SBCL/x86-64 (see :if-feature in the .asd); the portable
;;;; integer field.lisp stays as the fallback AND the differential oracle that
;;;; every VOP here is checked against (test/ cross-checks reference vs fast).
;;;;
;;;; Why VOPs and not portable Lisp: SBCL's generic bignum * and mod are already
;;;; tuned assembly, and any per-operation bignum allocation (ldb/ash/* on a
;;;; 512-bit product) loses to them by ~100x.  The only way to win is to keep the
;;;; field element in registers / fixed (unsigned-byte 64) limb arrays and do
;;;; multiply + Solinas reduction with no allocation at all — i.e. in asm.
;;;;
;;;; This SBCL (2.2.9) assembler supports MUL and ADC but not MULX/ADCX/ADOX
;;;; (BMI2/ADX), so the 256-bit multiply is classic mul + adc schoolbook (Comba).
;;;;
;;;; Bring-up brick: %MUL64 — 64x64 -> 128 (the atom of any bignum multiply).

(in-package #:secp256k1-fast)

(sb-c:defknown %mul64 ((unsigned-byte 64) (unsigned-byte 64))
    (values (unsigned-byte 64) (unsigned-byte 64))
    (sb-c:foldable sb-c:flushable sb-c:movable))

(defun %mul64 (a b)
  "Portable fallback for non-VOP-translated calls: (values lo hi) of a*b."
  (let ((p (* a b))) (values (ldb (byte 64 0) p) (ash p -64))))

(in-package #:sb-vm)

(sb-c:define-vop (secp256k1-fast::%mul64)
  (:translate secp256k1-fast::%mul64)
  (:policy :fast-safe)
  (:args (x :scs (unsigned-reg) :target rax)
         (y :scs (unsigned-reg unsigned-stack)))
  (:arg-types unsigned-num unsigned-num)
  (:temporary (:sc unsigned-reg :offset rax-offset :from (:argument 0) :to (:result 0)) rax)
  (:temporary (:sc unsigned-reg :offset rdx-offset :from :eval :to (:result 1)) rdx)
  (:results (lo :scs (unsigned-reg)) (hi :scs (unsigned-reg)))
  (:result-types unsigned-num unsigned-num)
  (:generator 6
    (move rax x)
    (inst mul rax y)              ; rdx:rax = rax * y
    (move lo rax)
    (move hi rdx)))

(in-package #:secp256k1-fast)
