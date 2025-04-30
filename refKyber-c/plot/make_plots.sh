#!/bin/bash
cat ../bench-ref.txt ../../mmCipher-c/bench-mm.txt | python3 make_plots.py bytes
cat ../bench-ref.txt ../../mmCipher-c/bench-mm.txt | python3 make_plots.py speed

