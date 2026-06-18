# secp256k1-fast

A fast, **dependency-free** secp256k1 in Common Lisp: ECDSA (RFC 6979 deterministic
nonces) and BIP-340 Schnorr, with its own SHA-256 / HMAC. No FFI, no libsecp, no
ironclad — all our own code.

```lisp
(asdf:load-system "secp256k1-fast")

(secp256k1-fast.schnorr:schnorr-verify pubkey32 msg32 sig64)   ; → T / NIL
(secp256k1-fast:ecdsa-verify pubkey-point hash32 r s)          ; → T / NIL
(secp256k1-fast:secp-pubkey privkey-int)                       ; → (x . y)
```

## Design

The point of this package is **performance that's auditable** — every fast path
is verified bit-for-bit against Bitcoin Core's compiled code via a differential
cross-check, which is the opposite of trusting a black-box FFI to libsecp.

- **`src/field.lisp`** is the base-field (F_p) arithmetic — the *portable integer
  reference* and the differential oracle.
- **`src/field-vops-x86-64.lisp` + `src/field-x86-64.lisp`** are the x86-64 fast
  backend (SBCL VOPs, loaded only on SBCL/x86-64). Field elements live in 4×64-bit
  limb arrays with no per-op allocation: a `mul`+`adc` Comba multiply, Solinas
  reduction for `p = 2²⁵⁶ − 2³² − 977`, and limb add/sub, all in inline assembly.
  On top: **Jacobian** point arithmetic, the **GLV endomorphism** (`φ(x,y) =
  (β·x,y) = λ·P`, halves the doublings), an **addition-chain inverse**, and
  **wNAF** with a static precomputed generator table for the verify hot path.
  These redefine `secp-mul-point` / `secp-mul-2`; the portable `point.lisp` stays
  as the fallback (other architectures) and the oracle.
- **`src/{ecdsa,schnorr}.lisp`** sit on top; **`src/{sha256,hmac}.lisp`** make it
  self-contained (no ironclad) and MVM-portable.

On an EPYC 7C13 (SBCL): **ECDSA verify ≈ 6,760/s, Schnorr ≈ 3,300/s** per core —
**~3.75× off libsecp256k1** (whose own `field_mul` is 20.8 ns vs our 22 ns — the
field primitives are at parity; the remaining gap is C vs Lisp + libsecp's
hand-tuning, not the math). 157× over the naïve affine start.

## Layout

```
secp256k1-fast.asd
src/ packages.lisp
     sha256.lisp hmac.lisp        ; self-contained hashing
     field.lisp scalar.lisp      ; F_p / F_n — portable reference + oracle
     point.lisp                  ; Jacobian, affine public API (portable fallback)
     ecdsa.lisp schnorr.lisp
     field-vops-x86-64.lisp      ; x86-64 field VOPs (mul/reduce/add/sub) [#+x86-64]
     field-x86-64.lisp           ; limb field + GLV + wNAF + chain inverse [#+x86-64]
test/ test.lisp                  ; SHA/HMAC/BIP340 vectors, round-trips, cross-check
```

## Correctness

```sh
sbcl --eval '(asdf:test-system "secp256k1-fast")'
```

- **Authoritative vectors:** SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 4231), the
  BIP-340 x-only public key for privkey 3, generator `1·G`, `n·G = ∞`.
- **Round-trips:** ECDSA and Schnorr sign→verify, plus tamper-rejection.
- **Differential equivalence:** `(secp256k1-fast.test:cross-check 500)` proves the
  output is **byte-for-byte identical** to [cl-consensus](../cl-consensus)'s crypto
  over random inputs — and that implementation is differential-tested bit-for-bit
  against Bitcoin Core's compiled `libbitcoinkernel`. So this package transitively
  inherits that assurance.

## Done

- **x86-64 SBCL VOP field backend** — `mul`+`adc` Comba multiply + Solinas reduce,
  limb add/sub, all inline asm, no allocation. (ADX `mulx`/`adcx`/`adox` was
  measured *not* to help here — even libsecp's own C regresses with `-march=native`
  on this CPU, and it ships no hand-asm path — so the plain `mul`/`adc` design is
  right.)
- **GLV endomorphism**, **wNAF** (static generator table), **addition-chain
  inverse** — the algorithmic stack that took us to 3.75× of libsecp.

## Roadmap

- **Multicore** — the fast-path scratch buffers are module-level (single-threaded);
  make them thread-local and verification (embarrassingly parallel) scales across
  all cores. On this 116-core box that's ~670k verify/s aggregate — well past
  single-core libsecp. The real win for IBD wall-clock.
- **aarch64 VOPs** (`mul`/`umulh`), or modus-emitted aarch64 for the MVM build.
- **MVM-native field arithmetic** once MVM is ANSI-CL (shared limb layout). The
  endgame: this is the crypto a bare-metal Lisp Bitcoin node runs.
