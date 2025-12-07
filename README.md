#   mmCipher-artifact

Version: December 6, 2025

This is an artifact for: Hongxiao Wang, Ron Steinfeld, Markku-Juhani O.
Saarinen, Muhammed F. Esgin, and Siu-Ming Yiu: _"mmCipher: Batching
Post-Quantum Public Key Encryption Made Bandwidth-Optimal."_
To appear in USENIX Security 2026.
Preprint: [IACR ePrint 2025/1000](https://eprint.iacr.org/2025/1000.pdf)

A multi-message multi-recipient PKE/KEM enables the batch encryption of
multiple messages (as a message vector) for multiple independent recipients
in a single operation, significantly reducing costs, particularly bandwidth,
compared to the trivial solution of encrypting each message individually.

We provide self-contained Python and portable C implementations of the
scheme (with some aspects that may need further optimization for
production-level deployment). The artifact also contains the code used for
generating the comparative benchmarks reported in this work, source code
for ZK proof experiments using the LaZer Library, and scripts and tools
used for security parameter selection (computation of lattice parameter
sets and decryption failure probabilities).


##  Directory Structure

What's here:
```
mmCipher-artifact
├── mmCipher-c        # Plain C Implementation of mmCipher. Used for benchmarks.
├── mmCipher-py       # Python model for mmCipher, compatible with the C code.
├── mmCipher-pkzk     # ZK proofs of public key validity with LaZer.
├── refKyber-c        # Plain C Kyber ref code for "apples-to-apples" benchmarks.
├── pr-fail-dec       # Computation of decryption/decaps failure probabilities.
├── param-sage        # SageMath lattice parameter selection/exploration scripts.
├── LICENSE           # MIT License
└── README.md         # this file
```

Each directory contains a `README.md` with further instructions.

##  USENIX Security 2026 Citation

This artifact contains source code and scripts related to USENIX Security
2026 paper:
```
@InProceedings{   WSSEY26,
  author    = {Hongxiao Wang and Ron Steinfeld and Markku-Juhani O.
                  Saarinen and Muhammed F. Esgin and Siu-Ming Yiu},
  editor    = {Ben Stock and Ben Stock},
  title     = {{mmCipher}: Batching Post-Quantum Public Key Encryption
                  Made Bandwidth-Optimal},
  booktitle = {35th {USENIX} Security Symposium, {USENIX} Security 2026,
                  Baltimore, MD, USA, August 12-14, 2026},
  note      = {Full version is available as IACR ePrint Report
                  2025/1000},
  url       = {https://eprint.iacr.org/2025/1000},
  pages     = {(to appear)},
  publisher = {{USENIX} Association},
  year      = {2026}
}
```

