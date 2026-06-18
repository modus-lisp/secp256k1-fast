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

;;; ---------------------------------------------------------------------------
;;; %MUL256 — 256x256 -> 512-bit multiply (Comba / product scanning) on pinned
;;; (unsigned-byte 64) limb arrays, NO allocation.  This is the field hot path's
;;; product step; reduction (Solinas) is the next VOP.  mul + adc (no MULX/ADX
;;; on this SBCL).  Measured: ~18x faster than SBCL's (mod (* a b) p) full mul,
;;; product-only, on this box.  Encoding of the MUL instruction cross-checked
;;; byte-identical against modus's verified x86-64 encoder.
;;; ---------------------------------------------------------------------------

(in-package #:secp256k1-fast)

(sb-c:defknown %mul256
    (sb-sys:system-area-pointer sb-sys:system-area-pointer sb-sys:system-area-pointer)
    (values) ())

(defun %mul256 (pa pb po)
  "Portable SAP fallback (non-VOP): out[0..7] = a[0..3] * b[0..3]."
  (flet ((rd (p i) (sb-sys:sap-ref-64 p (* i 8))))
    (let ((prod (* (loop for i below 4 sum (ash (rd pa i) (* i 64)))
                   (loop for i below 4 sum (ash (rd pb i) (* i 64))))))
      (dotimes (i 8) (setf (sb-sys:sap-ref-64 po (* i 8)) (ldb (byte 64 (* i 64)) prod)))
      (values))))

(in-package #:sb-vm)

(sb-c:define-vop (secp256k1-fast::%mul256)
  (:translate secp256k1-fast::%mul256)
  (:policy :fast-safe)
  (:args (pa :scs (sap-reg)) (pb :scs (sap-reg)) (po :scs (sap-reg)))
  (:arg-types system-area-pointer system-area-pointer system-area-pointer)
  (:temporary (:sc unsigned-reg :offset rax-offset) rax)
  (:temporary (:sc unsigned-reg :offset rdx-offset) rdx)
  (:temporary (:sc unsigned-reg) c0)
  (:temporary (:sc unsigned-reg) c1)
  (:temporary (:sc unsigned-reg) c2)
  (:generator 120
    (inst xor c0 c0) (inst xor c1 c1) (inst xor c2 c2)
    (dotimes (k 7)                                  ; product-scanning columns 0..6
      (loop for i from (max 0 (- k 3)) to (min 3 k) do
        (let ((j (- k i)))
          (inst mov rax (ea (* i 8) pa))
          (inst mul rax (ea (* j 8) pb))            ; rdx:rax = a[i]*b[j]
          (inst add c0 rax)                         ; 3-word accumulate
          (inst adc c1 rdx)
          (inst adc c2 0)))
      (inst mov (ea (* k 8) po) c0)                 ; out[k] = low word of column
      (inst mov c0 c1) (inst mov c1 c2) (inst xor c2 c2))   ; shift accumulator down
    (inst mov (ea 56 po) c0)))                      ; out[7]

(in-package #:secp256k1-fast)

(defun mul256! (a b out)
  "out[0..7] = a[0..3] * b[0..3], all (simple-array (unsigned-byte 64)).  No alloc."
  (declare (type (simple-array (unsigned-byte 64) (4)) a b)
           (type (simple-array (unsigned-byte 64) (8)) out)
           (optimize (speed 3) (safety 0)))
  (sb-sys:with-pinned-objects (a b out)
    (%mul256 (sb-sys:vector-sap a) (sb-sys:vector-sap b) (sb-sys:vector-sap out))))
