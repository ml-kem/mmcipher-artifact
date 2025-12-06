#   refKyber-c

This is the benchmark code used for "apples-to-apples" comparison between
plain C implementations of Kyber and mmCipher.

There is a similar `Makefile` to the mmCipher benchmark, with equivalent
compiler settings. The script names are also the same; `run_bench.sh`
creates a text file `bench.txt`.
```
./run_bench.sh
```

For purposes of reporting, the function names in the Kyber implementation
have been mapped to the ML-KEM (CCA) and K-PKE (CPA) names from
[FIPS 203](https://doi.org/10.6028/NIST.FIPS.203).


##  Reference Kyber code

The `kyber` directory contains commit `4768bd3` (from Feb 16, 2025)
of the original Kyber
[reference implementation](https://github.com/pq-crystals/kyber).
Only its `.git` history has been removed.
This part was placed in Public Domain (cc0) by its authors.

To replace the code with a fresh clone:
```
rm -rf kyber
git clone https://github.com/pq-crystals/kyber.git
```

