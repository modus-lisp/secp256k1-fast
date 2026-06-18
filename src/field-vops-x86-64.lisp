;;;; field-vops-x86-64.lisp — x86-64 field-arithmetic VOPs (SBCL inline assembly).
;;;;
;;;; Loaded ONLY on SBCL/x86-64, and BEFORE field-x86-64.lisp — SBCL only uses a
;;;; :translate VOP in compiled code if the VOP was registered when that code was
;;;; compiled.  Definitions and their callers therefore live in SEPARATE files
;;;; (ASDF compiles+loads this one fully before compiling the callers), exactly as
;;;; SBCL itself orders its VOP files.  (In the same file under compile-file the
;;;; VOP registers only at load time — too late — and the compiler emits a slow
;;;; full CALL instead of the inline asm.)
;;;;
;;;; All operate on pinned (unsigned-byte 64) limb arrays via SAP, no allocation.
;;;; Solinas reduction for p = 2^256 - 2^32 - 977 (2^256 == 2^32+977 == c mod p).
;;;; This SBCL has MUL/ADC but not MULX/ADCX/ADOX → classic mul+adc Comba.
;;;; MUL encoding cross-checked byte-identical vs modus's verified encoder.

(in-package #:secp256k1-fast)

(sb-c:defknown %mul64 ((unsigned-byte 64) (unsigned-byte 64))
    (values (unsigned-byte 64) (unsigned-byte 64))
    (sb-c:foldable sb-c:flushable sb-c:movable))
(sb-c:defknown %mul256
    (sb-sys:system-area-pointer sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())
(sb-c:defknown %reducep
    (sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())
(sb-c:defknown %fadd
    (sb-sys:system-area-pointer sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())
(sb-c:defknown %fsub
    (sb-sys:system-area-pointer sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())

(in-package #:sb-vm)

(sb-c:define-vop (secp256k1-fast::%mul64)
  (:translate secp256k1-fast::%mul64) (:policy :fast-safe)
  (:args (x :scs (unsigned-reg) :target rax) (y :scs (unsigned-reg unsigned-stack)))
  (:arg-types unsigned-num unsigned-num)
  (:temporary (:sc unsigned-reg :offset rax-offset :from (:argument 0) :to (:result 0)) rax)
  (:temporary (:sc unsigned-reg :offset rdx-offset :from :eval :to (:result 1)) rdx)
  (:results (lo :scs (unsigned-reg)) (hi :scs (unsigned-reg)))
  (:result-types unsigned-num unsigned-num)
  (:generator 6 (move rax x) (inst mul rax y) (move lo rax) (move hi rdx)))

(sb-c:define-vop (secp256k1-fast::%mul256)
  (:translate secp256k1-fast::%mul256) (:policy :fast-safe)
  (:args (pa :scs (sap-reg)) (pb :scs (sap-reg)) (po :scs (sap-reg)))
  (:arg-types system-area-pointer system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg :offset rax-offset) rax) (:temporary (:sc unsigned-reg :offset rdx-offset) rdx)
  (:temporary (:sc unsigned-reg) c0) (:temporary (:sc unsigned-reg) c1) (:temporary (:sc unsigned-reg) c2)
  (:generator 120
    (inst xor c0 c0) (inst xor c1 c1) (inst xor c2 c2)
    (dotimes (k 7)                                    ; product-scanning columns 0..6
      (loop for i from (max 0 (- k 3)) to (min 3 k) do
        (let ((j (- k i)))
          (inst mov rax (ea (* i 8) pa)) (inst mul rax (ea (* j 8) pb))
          (inst add c0 rax) (inst adc c1 rdx) (inst adc c2 0)))
      (inst mov (ea (* k 8) po) c0) (inst mov c0 c1) (inst mov c1 c2) (inst xor c2 c2))
    (inst mov (ea 56 po) c0)))

(sb-c:define-vop (secp256k1-fast::%reducep)
  (:translate secp256k1-fast::%reducep) (:policy :fast-safe)
  (:args (pt :scs (sap-reg)) (po :scs (sap-reg))) (:arg-types system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg :offset rax-offset) rax) (:temporary (:sc unsigned-reg :offset rdx-offset) rdx)
  (:temporary (:sc unsigned-reg) cc) (:temporary (:sc unsigned-reg) r0) (:temporary (:sc unsigned-reg) r1)
  (:temporary (:sc unsigned-reg) r2) (:temporary (:sc unsigned-reg) r3) (:temporary (:sc unsigned-reg) s0) (:temporary (:sc unsigned-reg) s1)
  (:generator 80
    (inst mov cc #x1000003D1)
    (inst mov rax (ea 32 pt)) (inst mul rax cc) (inst add rax (ea 0 pt)) (inst adc rdx 0) (inst mov r0 rax) (inst mov s0 rdx)
    (inst mov rax (ea 40 pt)) (inst mul rax cc) (inst add rax (ea 8 pt)) (inst adc rdx 0) (inst add rax s0) (inst adc rdx 0) (inst mov r1 rax) (inst mov s0 rdx)
    (inst mov rax (ea 48 pt)) (inst mul rax cc) (inst add rax (ea 16 pt)) (inst adc rdx 0) (inst add rax s0) (inst adc rdx 0) (inst mov r2 rax) (inst mov s0 rdx)
    (inst mov rax (ea 56 pt)) (inst mul rax cc) (inst add rax (ea 24 pt)) (inst adc rdx 0) (inst add rax s0) (inst adc rdx 0) (inst mov r3 rax) (inst mov s0 rdx)
    (inst mov rax s0) (inst mul rax cc) (inst add r0 rax) (inst adc r1 rdx) (inst adc r2 0) (inst adc r3 0) (inst mov s0 0) (inst adc s0 0)
    (inst mov rax s0) (inst mul rax cc) (inst add r0 rax) (inst adc r1 0) (inst adc r2 0) (inst adc r3 0) (inst mov s0 0) (inst adc s0 0)
    (inst mov rax s0) (inst mul rax cc) (inst add r0 rax) (inst adc r1 0) (inst adc r2 0) (inst adc r3 0)
    (inst mov rdx r0) (inst mov cc r1) (inst mov s0 r2) (inst mov s1 r3)
    (inst mov rax #xFFFFFFFEFFFFFC2F) (inst sub rdx rax) (inst sbb cc -1) (inst sbb s0 -1) (inst sbb s1 -1)
    (inst cmov :nc r0 rdx) (inst cmov :nc r1 cc) (inst cmov :nc r2 s0) (inst cmov :nc r3 s1)
    (inst mov (ea 0 po) r0) (inst mov (ea 8 po) r1) (inst mov (ea 16 po) r2) (inst mov (ea 24 po) r3)))

(sb-c:define-vop (secp256k1-fast::%fadd)
  (:translate secp256k1-fast::%fadd) (:policy :fast-safe)
  (:args (pa :scs (sap-reg)) (pb :scs (sap-reg)) (po :scs (sap-reg))) (:arg-types system-area-pointer system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg :offset rax-offset) rax) (:temporary (:sc unsigned-reg :offset rdx-offset) rdx)
  (:temporary (:sc unsigned-reg) cc) (:temporary (:sc unsigned-reg) co)
  (:temporary (:sc unsigned-reg) r0) (:temporary (:sc unsigned-reg) r1) (:temporary (:sc unsigned-reg) r2) (:temporary (:sc unsigned-reg) r3)
  (:generator 30
    (inst mov r0 (ea 0 pa)) (inst add r0 (ea 0 pb)) (inst mov r1 (ea 8 pa)) (inst adc r1 (ea 8 pb))
    (inst mov r2 (ea 16 pa)) (inst adc r2 (ea 16 pb)) (inst mov r3 (ea 24 pa)) (inst adc r3 (ea 24 pb))
    (inst mov co 0) (inst adc co 0) (inst mov cc #x1000003D1)
    (inst mov rax co) (inst mul rax cc) (inst add r0 rax) (inst adc r1 0) (inst adc r2 0) (inst adc r3 0)
    (inst mov co 0) (inst adc co 0) (inst mov rax co) (inst mul rax cc) (inst add r0 rax) (inst adc r1 0) (inst adc r2 0) (inst adc r3 0)
    (inst add r0 cc) (inst adc r1 0) (inst adc r2 0) (inst adc r3 0)         ; +c overflow trick
    (inst mov co 0) (inst adc co 0) (inst sub co 1) (inst and co cc)
    (inst sub r0 co) (inst sbb r1 0) (inst sbb r2 0) (inst sbb r3 0)
    (inst mov (ea 0 po) r0) (inst mov (ea 8 po) r1) (inst mov (ea 16 po) r2) (inst mov (ea 24 po) r3)))

(sb-c:define-vop (secp256k1-fast::%fsub)
  (:translate secp256k1-fast::%fsub) (:policy :fast-safe)
  (:args (pa :scs (sap-reg)) (pb :scs (sap-reg)) (po :scs (sap-reg))) (:arg-types system-area-pointer system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg) cc) (:temporary (:sc unsigned-reg) bo)
  (:temporary (:sc unsigned-reg) r0) (:temporary (:sc unsigned-reg) r1) (:temporary (:sc unsigned-reg) r2) (:temporary (:sc unsigned-reg) r3)
  (:generator 24
    (inst mov r0 (ea 0 pa)) (inst sub r0 (ea 0 pb)) (inst mov r1 (ea 8 pa)) (inst sbb r1 (ea 8 pb))
    (inst mov r2 (ea 16 pa)) (inst sbb r2 (ea 16 pb)) (inst mov r3 (ea 24 pa)) (inst sbb r3 (ea 24 pb))
    (inst sbb bo bo) (inst mov cc #x1000003D1) (inst and bo cc)              ; add c back iff borrow
    (inst sub r0 bo) (inst sbb r1 0) (inst sbb r2 0) (inst sbb r3 0)
    (inst mov (ea 0 po) r0) (inst mov (ea 8 po) r1) (inst mov (ea 16 po) r2) (inst mov (ea 24 po) r3)))
