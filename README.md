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

## Status & disclaimer

A clean-room, from-scratch implementation — differential-tested against Bitcoin
Core's script vectors (via [cl-consensus](../cl-consensus)) and byte-identical to
cl-consensus's crypto. It is **research / educational software, not audited.**
The hot paths use `(safety 0)` and are **NOT guaranteed constant-time** — do not
use this to sign with keys protecting real funds without an independent
side-channel review. No warranty (see [LICENSE](LICENSE)).

## Design

The point of this package is **performance that's auditable** — the fast path is
checked bit-for-bit against the portable bignum reference in-tree, and
transitively against Bitcoin Core (via cl-consensus's `libbitcoinkernel`
differential regression, which runs on this crypto). That's the opposite of
trusting a black-box FFI to libsecp.

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

On an EPYC 7C13 (SBCL): **ECDSA verify ≈ 7–8k/s, Schnorr ≈ 3.3–3.5k/s** per core
— a few× off libsecp256k1 (whose own `field_mul` is 20.8 ns vs our 22 ns — the
field primitives are at parity; the remaining gap is C vs Lisp + libsecp's
hand-tuning, not the math). ~157× over the naïve affine start. Verify is
embarrassingly parallel: ~242k verify/s aggregate at 64 threads (see
`thread-test`). Numbers vary with CPU and SBCL version — reproduce with
`(secp256k1-fast.test:bench)`.

## Layout

```
secp256k1-fast.asd
run-tests.sh                     ; one-command load + self-test (exits non-zero on failure)
src/ packages.lisp
     sha256.lisp hmac.lisp        ; self-contained hashing
     field.lisp scalar.lisp      ; F_p / F_n — portable reference + oracle
     point.lisp                  ; Jacobian, affine public API (portable fallback)
     ecdsa.lisp schnorr.lisp
     field-vops-x86-64.lisp      ; x86-64 field VOPs (mul/reduce/add/sub) [#+x86-64]
     field-x86-64.lisp           ; limb field + GLV + wNAF + chain inverse [#+x86-64]
test/ test.lisp                  ; SHA/HMAC/BIP340 vectors, round-trips, cross-check,
                                 ;   bench, multicore thread-test
```

## Build & test

**No external dependencies** — pure SBCL (its own SHA-256 / HMAC, no FFI, no
ironclad, no libsecp). The x86-64 VOP backend loads only on SBCL/x86-64;
elsewhere the portable `field.lisp` / `point.lisp` are used.

Make the repo visible to ASDF, either by symlinking it into the Quicklisp
local-projects dir:

```sh
ln -s "$PWD" ~/quicklisp/local-projects/secp256k1-fast
```

or by pushing the repo dir onto the central registry from the REPL:

```lisp
(push #p"/path/to/secp256k1-fast/" asdf:*central-registry*)
(asdf:load-system "secp256k1-fast")
```

Run the test suite — the one-command runner at the repo root loads the system and
runs the self-tests, exiting non-zero on any failure:

```sh
./run-tests.sh
```

Equivalently, from a REPL / `--eval`:

```sh
sbcl --eval '(asdf:test-system "secp256k1-fast")'
```

The benchmark (`(secp256k1-fast.test:bench)`) and the multicore verify test
(`(secp256k1-fast.test:thread-test)`) are also available once the test system is
loaded.

## Correctness

- **Authoritative vectors:** SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 4231), the
  BIP-340 x-only public key for privkey 3, generator `1·G`, `n·G = ∞`.
- **Round-trips:** ECDSA and Schnorr sign→verify, plus tamper-rejection.
- **Limb-backend cross-check:** on x86-64 the VOP `fmul!`/`fadd!`/`fsub!` are
  checked against the portable bignum reference over 20k random inputs.
- **Differential equivalence:** `(secp256k1-fast.test:cross-check 500)` proves the
  output is **byte-for-byte identical** to [cl-consensus](../cl-consensus)'s crypto
  over random inputs — and that implementation is differential-tested bit-for-bit
  against Bitcoin Core's compiled `libbitcoinkernel`. (cl-consensus now re-exports
  *this* crypto, so the cross-check is a self-consistency smoke test; the real
  Bitcoin Core differential lives in cl-consensus's regression suite. This check
  needs the sibling cl-consensus repo loadable and is **not** part of the default
  `run-tests.sh`.)

## Done

- **x86-64 SBCL VOP field backend** — `mul`+`adc` Comba multiply + Solinas reduce,
  limb add/sub, all inline asm, no allocation. (ADX `mulx`/`adcx`/`adox` was
  measured *not* to help here — even libsecp's own C regresses with `-march=native`
  on this CPU, and it ships no hand-asm path — so the plain `mul`/`adc` design is
  right.)
- **GLV endomorphism**, **wNAF** (static generator table), **addition-chain
  inverse** — the algorithmic stack that took us to 3.75× of libsecp.
- **Multicore verify** — the fast-path scratch buffers are now thread-local via
  `with-fresh-scratch`, so verification (embarrassingly parallel) scales across
  cores. `(secp256k1-fast.test:thread-test)` exercises it; ~242k verify/s
  aggregate at 64 threads on the EPYC box — well past single-core libsecp. The
  real win for IBD wall-clock.

## Roadmap

- **aarch64 VOPs** (`mul`/`umulh`), or modus-emitted aarch64 for the MVM build.
- **MVM-native field arithmetic** once MVM is ANSI-CL (shared limb layout). The
  endgame: this is the crypto a bare-metal Lisp Bitcoin node runs.

## License

MIT — see [LICENSE](LICENSE). No warranty; see the disclaimer above.
