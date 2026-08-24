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

(sb-c:defknown %mul256
    (sb-sys:system-area-pointer sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())
(sb-c:defknown %reducep
    (sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())
(sb-c:defknown %fadd
    (sb-sys:system-area-pointer sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())
(sb-c:defknown %fsub
    (sb-sys:system-area-pointer sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())
;; Montgomery reduction mod n (scalar field).  PT -> 9-limb scratch holding a
;; 512-bit product in limbs 0..7 (limb 8 is zeroed by the VOP); PO <- 4-limb
;; result = PT * R^-1 mod n, R = 2^256.  Lets the mod-n inverse run as a fixed
;; Fermat addition chain over limb arrays (no bignum extended-Euclid).
(sb-c:defknown %montredn
    (sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())

(in-package #:sb-vm)

;;; MUL is a ONE-operand instruction on x86-64: RDX:RAX <- RAX * SRC.  The accumulator is
;;; implicit, and SBCL's spelling of it has moved:
;;;
;;;   <= 2.2   (define-instruction mul (segment dst src))          two operands ARE the API
;;;   2.3-2.4  (... &prefix prefix src &optional junk)             two tolerated, warns, still correct
;;;   >= 2.5   (... &prefix prefix src)                            two operands => assembler error
;;;
;;; So the two-operand form compiled correctly through 2.4 and stops compiling at 2.5 with
;;; "invalid number of arguments: 4" out of the assembler.  There was never a window where it
;;; emitted wrong arithmetic, which is the one mercy here — these are field operations, and a
;;; wrong operand would be a wrong number rather than a crash.
;;;
;;; Both spellings are kept because the version that has to be supported is not a matter of
;;; taste: SBCL 2.2 is what several machines in this project actually run.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun %one-operand-mul-p ()
    "True when this SBCL wants (inst mul src) rather than (inst mul rax src).

Parsed from the version because SBCL publishes no feature for it.  An unparseable version is
assumed modern: 2.2 is the exception now, and guessing new fails loudly at compile time while
guessing old would fail on every current SBCL."
    (let* ((v (lisp-implementation-version))
           (dot (position #\. v))
           (major (and dot (parse-integer v :end dot :junk-allowed t)))
           (rest (and dot (subseq v (1+ dot))))
           (dot2 (and rest (position #\. rest)))
           (minor (and rest (parse-integer rest :end dot2 :junk-allowed t))))
      (if (and major minor)
          (or (> major 2) (and (= major 2) (>= minor 3)))
          t))))

(defmacro mul-by-rax (src)
  "MUL SRC, with RAX as the implicit multiplicand, spelled for this SBCL.

The :QWORD is not decoration.  With one operand there is no register to infer the operand size
from, so a MEMORY source leaves SBCL binding OPERAND-SIZE to NIL and the assembler dies with
\"The value NIL is not of type (MEMBER :DO-NOT-SET :QWORD :DWORD :WORD :BYTE)\".  That is what
the &prefix in (define-instruction mul (segment &prefix prefix src)) is for.  Every multiply here
is 64x64, so the size is stated unconditionally rather than only for the (ea ...) sites — one
spelling is easier to keep right than two."
  (if (%one-operand-mul-p) `(inst mul :qword ,src) `(inst mul rax ,src)))


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
          (inst mov rax (ea (* i 8) pa)) (mul-by-rax (ea (* j 8) pb))
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
    (inst mov rax (ea 32 pt)) (mul-by-rax cc) (inst add rax (ea 0 pt)) (inst adc rdx 0) (inst mov r0 rax) (inst mov s0 rdx)
    (inst mov rax (ea 40 pt)) (mul-by-rax cc) (inst add rax (ea 8 pt)) (inst adc rdx 0) (inst add rax s0) (inst adc rdx 0) (inst mov r1 rax) (inst mov s0 rdx)
    (inst mov rax (ea 48 pt)) (mul-by-rax cc) (inst add rax (ea 16 pt)) (inst adc rdx 0) (inst add rax s0) (inst adc rdx 0) (inst mov r2 rax) (inst mov s0 rdx)
    (inst mov rax (ea 56 pt)) (mul-by-rax cc) (inst add rax (ea 24 pt)) (inst adc rdx 0) (inst add rax s0) (inst adc rdx 0) (inst mov r3 rax) (inst mov s0 rdx)
    (inst mov rax s0) (mul-by-rax cc) (inst add r0 rax) (inst adc r1 rdx) (inst adc r2 0) (inst adc r3 0) (inst mov s0 0) (inst adc s0 0)
    (inst mov rax s0) (mul-by-rax cc) (inst add r0 rax) (inst adc r1 0) (inst adc r2 0) (inst adc r3 0) (inst mov s0 0) (inst adc s0 0)
    (inst mov rax s0) (mul-by-rax cc) (inst add r0 rax) (inst adc r1 0) (inst adc r2 0) (inst adc r3 0)
    (inst mov rdx r0) (inst mov cc r1) (inst mov s0 r2) (inst mov s1 r3)
    (inst mov rax #xFFFFFFFEFFFFFC2F) (inst sub rdx rax) (inst sbb cc -1) (inst sbb s0 -1) (inst sbb s1 -1)
    (inst cmov :nc r0 rdx) (inst cmov :nc r1 cc) (inst cmov :nc r2 s0) (inst cmov :nc r3 s1)
    (inst mov (ea 0 po) r0) (inst mov (ea 8 po) r1) (inst mov (ea 16 po) r2) (inst mov (ea 24 po) r3)))

(sb-c:define-vop (secp256k1-fast::%montredn)
  (:translate secp256k1-fast::%montredn) (:policy :fast-safe)
  (:args (pt :scs (sap-reg)) (po :scs (sap-reg))) (:arg-types system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg :offset rax-offset) rax) (:temporary (:sc unsigned-reg :offset rdx-offset) rdx)
  (:temporary (:sc unsigned-reg) np) (:temporary (:sc unsigned-reg) m) (:temporary (:sc unsigned-reg) cc)
  (:temporary (:sc unsigned-reg) nt)
  (:temporary (:sc unsigned-reg) r0) (:temporary (:sc unsigned-reg) r1) (:temporary (:sc unsigned-reg) r2) (:temporary (:sc unsigned-reg) r3)
  (:generator 200
    ;; SOS Montgomery reduction: t (9 limbs, [8] zeroed here) -> t*R^-1 mod n.
    (let ((n0 #xBFD25E8CD0364141) (n1 #xBAAEDCE6AF48A03B) (n2 #xFFFFFFFFFFFFFFFE) (n3 #xFFFFFFFFFFFFFFFF)
          (n0p #x4B0DFF665588B13F))
      (let ((nl (list n0 n1 n2 n3)))
        (inst mov :qword (ea 64 pt) 0)
        (dotimes (i 4)
          (inst mov rax (ea (* 8 i) pt)) (inst mov np n0p) (inst imul rax np) (inst mov m rax)  ; m = t[i]*n0' mod 2^64
          (inst xor cc cc)
          (dotimes (j 4)
            (inst mov rax m) (inst mov nt (nth j nl)) (mul-by-rax nt)        ; rdx:rax = m*n[j]
            (inst add rax (ea (* 8 (+ i j)) pt)) (inst adc rdx 0)
            (inst add rax cc) (inst adc rdx 0)
            (inst mov (ea (* 8 (+ i j)) pt) rax) (inst mov cc rdx))
          (inst add (ea (* 8 (+ i 4)) pt) cc)                                  ; fold carry into limb i+4
          (loop for k from (+ i 5) to 8 do (inst adc :qword (ea (* 8 k) pt) 0)))  ; ripple to limb 8
        ;; result in t[4..7](+t[8]); one conditional subtract of n
        (inst mov r0 (ea 32 pt)) (inst mov r1 (ea 40 pt)) (inst mov r2 (ea 48 pt)) (inst mov r3 (ea 56 pt))
        (inst mov np r0) (inst mov nt n0) (inst sub np nt)
        (inst mov m  r1) (inst mov nt n1) (inst sbb m nt)
        (inst mov cc r2) (inst mov nt n2) (inst sbb cc nt)
        (inst mov rdx r3) (inst mov nt n3) (inst sbb rdx nt)
        (inst mov rax (ea 64 pt)) (inst sbb rax 0)
        (inst cmov :nc r0 np) (inst cmov :nc r1 m) (inst cmov :nc r2 cc) (inst cmov :nc r3 rdx)
        (inst mov (ea 0 po) r0) (inst mov (ea 8 po) r1) (inst mov (ea 16 po) r2) (inst mov (ea 24 po) r3)))))

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
    (inst mov rax co) (mul-by-rax cc) (inst add r0 rax) (inst adc r1 0) (inst adc r2 0) (inst adc r3 0)
    (inst mov co 0) (inst adc co 0) (inst mov rax co) (mul-by-rax cc) (inst add r0 rax) (inst adc r1 0) (inst adc r2 0) (inst adc r3 0)
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
