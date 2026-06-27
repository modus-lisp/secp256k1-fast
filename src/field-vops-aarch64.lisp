;;;; field-vops-aarch64.lisp — arm64 (AArch64) field-arithmetic VOPs (SBCL asm).
;;;;
;;;; The arm64 twin of field-vops-x86-64.lisp.  SBCL's feature for AArch64 is
;;;; :ARM64 (uname calls it aarch64); the .asd gates this file on (:and :sbcl
;;;; :arm64).  Loaded BEFORE field-limb.lisp — SBCL only inlines a :translate VOP
;;;; in compiled code if the VOP was registered when that code was compiled, so
;;;; the definitions and their callers must live in SEPARATE files (ASDF compiles
;;;; + loads this one fully before compiling field-limb.lisp), exactly as on x86.
;;;;
;;;; Same five primitives, same algorithms, same SAP/limb-array ABI as the x86-64
;;;; backend — only the instruction selection differs.  field-limb.lisp names the
;;;; VOP symbols and is byte-for-byte identical across architectures; the portable
;;;; field.lisp / point.lisp remain the differential oracle that validates these.
;;;;
;;;;   %mul256    4x64 * 4x64 -> 8x64           Comba product-scanning (mul+umulh)
;;;;   %reducep   8x64 -> 4x64 mod p            Solinas, p = 2^256-2^32-977
;;;;   %fadd      (a+b) mod p                   add + conditional single subtract
;;;;   %fsub      (a-b) mod p                   sub + conditional add-back of c
;;;;   %montredn  9x64 -> 4x64 = t*R^-1 mod n   SOS Montgomery (n's limbs baked in)
;;;;
;;;; AArch64 notes vs x86-64:
;;;;   * load/store architecture — every limb is ldr'd into a register first;
;;;;     there are no memory-operand arithmetic forms.
;;;;   * 64x64->128 is mul (low 64) + umulh (high 64); neither touches flags.
;;;;   * carry chains use adds/adcs/adc and subs/sbcs/sbc.  As on every ARM,
;;;;     SUBS sets C=1 for *no borrow* (a>=b) — the inverse of x86's CF — so the
;;;;     conditional-subtract selects on :cs where x86 cmov's on :nc.
;;;;   * no CMOV; csel Rd,Ra,Rb,cond gives the same branch-free select.
;;;;   * 64-bit immediates can't be one instruction — SECP-LOAD-IMM64 emits the
;;;;     movz/movk sequence.

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
;; result = PT * R^-1 mod n, R = 2^256.  Same ABI as the x86-64 %montredn.
(sb-c:defknown %montredn
    (sb-sys:system-area-pointer sb-sys:system-area-pointer) (values) ())

(in-package #:sb-vm)

;;; Emit reg <- 64-bit immediate via movz + three movk's (always 4 instructions;
;;; correctness over code size).  movz zeroes the register and sets bits [15:0];
;;; each movk overwrites one further 16-bit lane without disturbing the rest.
(defun secp-load-imm64 (reg value)
  (inst movz reg (ldb (byte 16 0) value) 0)
  (inst movk reg (ldb (byte 16 16) value) 16)
  (inst movk reg (ldb (byte 16 32) value) 32)
  (inst movk reg (ldb (byte 16 48) value) 48))

;;; ---------------------------------------------------------------------------
;;; %mul256 — 4-limb x 4-limb -> 8-limb, product-scanning (Comba).
;;; Three-register running accumulator c2:c1:c0; each column sums its partial
;;; products (mul/umulh) into it, stores c0, then shifts the accumulator down.
;;; c2 never overflows: <=4 partial products per column, each <2^128.
;;; ---------------------------------------------------------------------------
(sb-c:define-vop (secp256k1-fast::%mul256)
  (:translate secp256k1-fast::%mul256) (:policy :fast-safe)
  (:args (pa :scs (sap-reg)) (pb :scs (sap-reg)) (po :scs (sap-reg)))
  (:arg-types system-area-pointer system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg) ra) (:temporary (:sc unsigned-reg) rb)
  (:temporary (:sc unsigned-reg) lo) (:temporary (:sc unsigned-reg) hi)
  (:temporary (:sc unsigned-reg) c0) (:temporary (:sc unsigned-reg) c1) (:temporary (:sc unsigned-reg) c2)
  (:generator 120
    (inst movz c0 0 0) (inst movz c1 0 0) (inst movz c2 0 0)
    (dotimes (k 7)                                      ; columns 0..6
      (loop for i from (max 0 (- k 3)) to (min 3 k) do
        (let ((j (- k i)))
          (inst ldr ra (@ pa (* i 8))) (inst ldr rb (@ pb (* j 8)))
          (inst mul lo ra rb) (inst umulh hi ra rb)
          (inst adds c0 c0 lo) (inst adcs c1 c1 hi) (inst adc c2 c2 zr-tn)))
      (inst str c0 (@ po (* k 8)))
      (inst mov c0 c1) (inst mov c1 c2) (inst movz c2 0 0))
    (inst str c0 (@ po 56))))

;;; ---------------------------------------------------------------------------
;;; %reducep — 512 -> 256 mod p, p = 2^256 - 2^32 - 977, with c = 2^32+977 =
;;; 0x1000003D1 (2^256 == c mod p).  Fold the high four limbs t[4..7] into the
;;; low four as t_lo + c*t_hi, then fold the <2^35 overflow back twice more, then
;;; one constant-time conditional subtract of p.  Mirrors the x86-64 VOP exactly.
;;; ---------------------------------------------------------------------------
(sb-c:define-vop (secp256k1-fast::%reducep)
  (:translate secp256k1-fast::%reducep) (:policy :fast-safe)
  (:args (pt :scs (sap-reg)) (po :scs (sap-reg))) (:arg-types system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg) cc) (:temporary (:sc unsigned-reg) x) (:temporary (:sc unsigned-reg) y)
  (:temporary (:sc unsigned-reg) lo) (:temporary (:sc unsigned-reg) hi) (:temporary (:sc unsigned-reg) s0)
  (:temporary (:sc unsigned-reg) r0) (:temporary (:sc unsigned-reg) r1)
  (:temporary (:sc unsigned-reg) r2) (:temporary (:sc unsigned-reg) r3)
  (:generator 80
    (secp-load-imm64 cc #x1000003D1)
    ;; r0 = t0 + c*t4 ; s0 = carry
    (inst ldr x (@ pt 32)) (inst mul lo x cc) (inst umulh hi x cc)
    (inst ldr y (@ pt 0)) (inst adds r0 lo y) (inst adc s0 hi zr-tn)
    ;; r1 = t1 + c*t5 + s0
    (inst ldr x (@ pt 40)) (inst mul lo x cc) (inst umulh hi x cc)
    (inst ldr y (@ pt 8)) (inst adds lo lo y) (inst adc hi hi zr-tn)
    (inst adds r1 lo s0) (inst adc s0 hi zr-tn)
    ;; r2 = t2 + c*t6 + s0
    (inst ldr x (@ pt 48)) (inst mul lo x cc) (inst umulh hi x cc)
    (inst ldr y (@ pt 16)) (inst adds lo lo y) (inst adc hi hi zr-tn)
    (inst adds r2 lo s0) (inst adc s0 hi zr-tn)
    ;; r3 = t3 + c*t7 + s0
    (inst ldr x (@ pt 56)) (inst mul lo x cc) (inst umulh hi x cc)
    (inst ldr y (@ pt 24)) (inst adds lo lo y) (inst adc hi hi zr-tn)
    (inst adds r3 lo s0) (inst adc s0 hi zr-tn)
    ;; fold s0*c (round 1 propagates the high half; s0 is now tiny after this)
    (inst mul lo s0 cc) (inst umulh hi s0 cc)
    (inst adds r0 r0 lo) (inst adcs r1 r1 hi) (inst adcs r2 r2 zr-tn) (inst adcs r3 r3 zr-tn) (inst adc s0 zr-tn zr-tn)
    (inst mul lo s0 cc)
    (inst adds r0 r0 lo) (inst adcs r1 r1 zr-tn) (inst adcs r2 r2 zr-tn) (inst adcs r3 r3 zr-tn) (inst adc s0 zr-tn zr-tn)
    (inst mul lo s0 cc)
    (inst adds r0 r0 lo) (inst adcs r1 r1 zr-tn) (inst adcs r2 r2 zr-tn) (inst adc r3 r3 zr-tn)
    ;; conditional subtract of p (p0=0xFFFFFFFEFFFFFC2F, p1..3 = all ones);
    ;; carry set after the chain => no borrow => result >= p => take subtracted.
    (secp-load-imm64 x #xFFFFFFFEFFFFFC2F) (secp-load-imm64 y #xFFFFFFFFFFFFFFFF)
    (inst subs lo r0 x) (inst sbcs hi r1 y) (inst sbcs s0 r2 y) (inst sbcs x r3 y)
    (inst csel r0 lo r0 :cs) (inst csel r1 hi r1 :cs) (inst csel r2 s0 r2 :cs) (inst csel r3 x r3 :cs)
    (inst str r0 (@ po 0)) (inst str r1 (@ po 8)) (inst str r2 (@ po 16)) (inst str r3 (@ po 24))))

;;; ---------------------------------------------------------------------------
;;; %montredn — SOS Montgomery reduction mod n (the curve order).  In-place on
;;; the 9-limb scratch PT: limb 8 is zeroed here; four rounds each cancel one low
;;; limb (m = t[i]*n0' mod 2^64, then t += m*n << 64*i), leaving t*R^-1 in
;;; t[4..8]; one constant-time conditional subtract of n -> PO.  n's limbs and
;;; n0' = -n^-1 mod 2^64 are baked in.  Mirrors the x86-64 %montredn exactly.
;;; ---------------------------------------------------------------------------
(sb-c:define-vop (secp256k1-fast::%montredn)
  (:translate secp256k1-fast::%montredn) (:policy :fast-safe)
  (:args (pt :scs (sap-reg)) (po :scs (sap-reg))) (:arg-types system-area-pointer system-area-pointer)
  ;; arm64 unsigned-reg has only 14 allocatable locations, and the two SAP args
  ;; share that file — so n's limbs and n0' are loaded on demand into NJ (a single
  ;; scratch) rather than pinned in four registers.  movz/movk don't touch NZCV,
  ;; so reloading NJ mid-chain leaves the conditional-subtract borrow intact.
  (:temporary (:sc unsigned-reg) m) (:temporary (:sc unsigned-reg) cc) (:temporary (:sc unsigned-reg) nj)
  (:temporary (:sc unsigned-reg) lo) (:temporary (:sc unsigned-reg) hi) (:temporary (:sc unsigned-reg) t0)
  (:temporary (:sc unsigned-reg) r0) (:temporary (:sc unsigned-reg) r1)
  (:temporary (:sc unsigned-reg) r2) (:temporary (:sc unsigned-reg) r3)
  (:generator 200
    (let ((nl (list #xBFD25E8CD0364141 #xBAAEDCE6AF48A03B #xFFFFFFFFFFFFFFFE #xFFFFFFFFFFFFFFFF))
          (n0p #x4B0DFF665588B13F))
      (inst str zr-tn (@ pt 64))                          ; zero limb 8
      (dotimes (i 4)
        (inst ldr t0 (@ pt (* 8 i)))
        (secp-load-imm64 nj n0p) (inst mul m t0 nj)        ; m = t[i] * n0' mod 2^64
        (inst movz cc 0 0)                                ; running carry
        (dotimes (j 4)
          (secp-load-imm64 nj (nth j nl))
          (inst mul lo m nj) (inst umulh hi m nj)          ; hi:lo = m * n[j]
          (inst ldr t0 (@ pt (* 8 (+ i j))))
          (inst adds lo lo t0) (inst adc hi hi zr-tn)      ; + t[i+j]
          (inst adds lo lo cc) (inst adc hi hi zr-tn)      ; + carry-in
          (inst str lo (@ pt (* 8 (+ i j))))
          (inst mov cc hi))
        (inst ldr t0 (@ pt (* 8 (+ i 4))))                ; fold carry into limb i+4
        (inst adds t0 t0 cc) (inst str t0 (@ pt (* 8 (+ i 4))))
        (loop for k from (+ i 5) to 8 do                  ; ripple to limb 8
          (inst ldr t0 (@ pt (* 8 k))) (inst adcs t0 t0 zr-tn) (inst str t0 (@ pt (* 8 k)))))
      ;; result in t[4..8]; one conditional subtract of n (reuse m/cc/lo/hi as the
      ;; difference limbs — they are dead past the reduction loop).
      (inst ldr r0 (@ pt 32)) (inst ldr r1 (@ pt 40)) (inst ldr r2 (@ pt 48)) (inst ldr r3 (@ pt 56))
      (secp-load-imm64 nj (nth 0 nl)) (inst subs m r0 nj)
      (secp-load-imm64 nj (nth 1 nl)) (inst sbcs cc r1 nj)
      (secp-load-imm64 nj (nth 2 nl)) (inst sbcs lo r2 nj)
      (secp-load-imm64 nj (nth 3 nl)) (inst sbcs hi r3 nj)
      (inst ldr t0 (@ pt 64)) (inst sbcs t0 t0 zr-tn)     ; borrow from the top limb
      (inst csel r0 m r0 :cs) (inst csel r1 cc r1 :cs) (inst csel r2 lo r2 :cs) (inst csel r3 hi r3 :cs)
      (inst str r0 (@ po 0)) (inst str r1 (@ po 8)) (inst str r2 (@ po 16)) (inst str r3 (@ po 24)))))

;;; ---------------------------------------------------------------------------
;;; %fadd — (a + b) mod p.  Add the four limbs; fold the carry-out as +c (twice,
;;; since c*carry can re-carry), add one more c and subtract it back unless that
;;; produced a final carry — the canonical add-then-conditional-subtract.
;;; ---------------------------------------------------------------------------
(sb-c:define-vop (secp256k1-fast::%fadd)
  (:translate secp256k1-fast::%fadd) (:policy :fast-safe)
  (:args (pa :scs (sap-reg)) (pb :scs (sap-reg)) (po :scs (sap-reg)))
  (:arg-types system-area-pointer system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg) cc) (:temporary (:sc unsigned-reg) co)
  (:temporary (:sc unsigned-reg) lo) (:temporary (:sc unsigned-reg) t0)
  (:temporary (:sc unsigned-reg) r0) (:temporary (:sc unsigned-reg) r1)
  (:temporary (:sc unsigned-reg) r2) (:temporary (:sc unsigned-reg) r3)
  (:generator 30
    (inst ldr r0 (@ pa 0))  (inst ldr t0 (@ pb 0))  (inst adds r0 r0 t0)
    (inst ldr r1 (@ pa 8))  (inst ldr t0 (@ pb 8))  (inst adcs r1 r1 t0)
    (inst ldr r2 (@ pa 16)) (inst ldr t0 (@ pb 16)) (inst adcs r2 r2 t0)
    (inst ldr r3 (@ pa 24)) (inst ldr t0 (@ pb 24)) (inst adcs r3 r3 t0)
    (inst adc co zr-tn zr-tn)                            ; co = carry out (0/1)
    (secp-load-imm64 cc #x1000003D1)
    (inst mul lo co cc)                                  ; co*c (co in {0,1} -> fits 64)
    (inst adds r0 r0 lo) (inst adcs r1 r1 zr-tn) (inst adcs r2 r2 zr-tn) (inst adcs r3 r3 zr-tn)
    (inst adc co zr-tn zr-tn) (inst mul lo co cc)
    (inst adds r0 r0 lo) (inst adcs r1 r1 zr-tn) (inst adcs r2 r2 zr-tn) (inst adcs r3 r3 zr-tn)
    (inst adds r0 r0 cc) (inst adcs r1 r1 zr-tn) (inst adcs r2 r2 zr-tn) (inst adcs r3 r3 zr-tn)  ; +c
    (inst adc co zr-tn zr-tn) (inst subs co co 1) (inst and co co cc)  ; co = (no final carry) ? c : 0
    (inst subs r0 r0 co) (inst sbcs r1 r1 zr-tn) (inst sbcs r2 r2 zr-tn) (inst sbc r3 r3 zr-tn)
    (inst str r0 (@ po 0)) (inst str r1 (@ po 8)) (inst str r2 (@ po 16)) (inst str r3 (@ po 24))))

;;; ---------------------------------------------------------------------------
;;; %fsub — (a - b) mod p.  Subtract the four limbs; if it borrowed, add c back
;;; (the 2^256 wrap is +c mod p).  sbc bo,zr,zr materialises 0 / all-ones for
;;; "no borrow / borrow" (C=0 means borrow on ARM), masked to c.
;;; ---------------------------------------------------------------------------
(sb-c:define-vop (secp256k1-fast::%fsub)
  (:translate secp256k1-fast::%fsub) (:policy :fast-safe)
  (:args (pa :scs (sap-reg)) (pb :scs (sap-reg)) (po :scs (sap-reg)))
  (:arg-types system-area-pointer system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg) cc) (:temporary (:sc unsigned-reg) bo) (:temporary (:sc unsigned-reg) t0)
  (:temporary (:sc unsigned-reg) r0) (:temporary (:sc unsigned-reg) r1)
  (:temporary (:sc unsigned-reg) r2) (:temporary (:sc unsigned-reg) r3)
  (:generator 24
    (inst ldr r0 (@ pa 0))  (inst ldr t0 (@ pb 0))  (inst subs r0 r0 t0)
    (inst ldr r1 (@ pa 8))  (inst ldr t0 (@ pb 8))  (inst sbcs r1 r1 t0)
    (inst ldr r2 (@ pa 16)) (inst ldr t0 (@ pb 16)) (inst sbcs r2 r2 t0)
    (inst ldr r3 (@ pa 24)) (inst ldr t0 (@ pb 24)) (inst sbcs r3 r3 t0)
    (inst sbc bo zr-tn zr-tn)                            ; bo = borrow ? all-ones : 0
    (secp-load-imm64 cc #x1000003D1) (inst and bo bo cc)
    (inst subs r0 r0 bo) (inst sbcs r1 r1 zr-tn) (inst sbcs r2 r2 zr-tn) (inst sbc r3 r3 zr-tn)
    (inst str r0 (@ po 0)) (inst str r1 (@ po 8)) (inst str r2 (@ po 16)) (inst str r3 (@ po 24))))
