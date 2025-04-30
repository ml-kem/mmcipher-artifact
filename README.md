#   mmCipher-artifact

A multi-message multi-recipient PKE/KEM enables the batch encryption of
multiple messages (as a message vector) for multiple independent recipients
in a single operation, significantly reducing costs, particularly bandwidth,
compared to the trivial solution of encrypting each message individually.

What's here:
```
mmCipher-artifact
├── mmCipher-c       # Plain C Implementation of mmCipher. Used for benchmarks.
├── mmCipher-py      # Python model for mmCipher, compatible with the C code.
├── mmCipher-pkzk    # ZK proofs of public key validity with LaZer.
├── refKyber-c       # Plain C Kyber ref code for "apples-to-apples" benchmarks.
├── pr-fail-dec      # Computation of decryption/decaps failure probabilities.
├── param-sage       # SageMath lattice parameter selection/exploration scripts.
└── README.md        # this file
```

