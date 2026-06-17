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

The point of this package is **performance with a clean seam for going faster**:

- **`src/field.lisp`** is the base-field (F_p) arithmetic — the *portable integer
  reference*. It is deliberately the narrow waist of the library. A fast backend
  (SBCL VOPs over 4×64-bit limbs, or MVM-native code using `mul64lo`/`mul64hi`/
  `acc128` + Solinas reduction for `p = 2²⁵⁶ − 2³² − 977`) replaces `secp-mul` /
  `secp-sq` / `secp-inv` here, and everything above is untouched. The reference
  stays as the differential oracle the fast path is checked against.
- **`src/point.lisp`** runs the scalar-multiplication hot path in **Jacobian
  projective coordinates** (one inverse per scalar mult, not ~384), and uses
  **Shamir's trick** (`secp-mul-2`) for the `u1·G + u2·Q` verify pattern (one
  shared chain of doublings). Public points stay affine `(x . y)`.
- **`src/{ecdsa,schnorr}.lisp`** sit on top; **`src/{sha256,hmac}.lisp`** make it
  self-contained and MVM-portable.

On an EPYC 7C13 (SBCL): **ECDSA verify ≈ 505/s, Schnorr ≈ 466/s** per core — ~11.6×
over a naïve affine implementation, before any assembly.

## Layout

```
secp256k1-fast.asd
src/ packages.lisp
     sha256.lisp hmac.lisp     ; self-contained hashing
     field.lisp                ; F_p — the VOP/MVM backend seam
     scalar.lisp               ; F_n (curve order)
     point.lisp                ; Jacobian + Shamir, affine public API
     ecdsa.lisp schnorr.lisp
test/ test.lisp                ; SHA/HMAC/BIP340 vectors, round-trips, cross-check
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

## Roadmap

- SBCL VOP field backend (x86-64 `mulx`/`adcx`/`adox`, aarch64 `mul`/`umulh`)
  behind `#+x86-64` / `#+arm64`, reference kept as fallback + oracle.
- MVM-native field arithmetic once MVM is ANSI-CL (shared limb layout with the
  VOP path). The endgame: this is the crypto a bare-metal Lisp Bitcoin node runs.
- Optional GLV endomorphism (constants already gathered) and a generator comb for
  signing throughput.
