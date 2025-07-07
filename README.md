# On the Use of ECDSA with Hierarchical Public Key Delegation in Identity-based Scenarios

> Submitted to the IACR Communications in Cryptology (CiC), 2025.

**Abstract**. This repository contains the code associated with our paper "On the Use of ECDSA with Hierarchical Public Key Delegation in Identity-based Scenarios", submitted to the IACR Communications in Cryptology. Our implementation contains 3 main components: (i) the LaTeX source code with the authorship anonymized, (ii) the implementation of the schemes discussed in the paper with OpenSSL, and (iii) a Python script to analyze the results.
## Requirements

We use the following packages to run our proof of concept:
1. OpenSSL v3.5.0: code written in C
2. gcc v14.2.0: compiler for C code
3. Python v3.13.2: scripts for performance analysis
4. Numpy v2.2.4: numerical calculation
5. CSV v1.0: csv file handling
We are using a common off-the-shelf equipment (Intel i7-6500U CPU @2.50GHz) to run the experiments.
## Running the code

1. To compile the code, run gcc with flags ``-lssl -lcrypto``. We have added the binaries also, but no errors should appear.
2. We make a total of $N = 10000$ experiments to obtain the numerical values presented in the article. The script  ``run.sh`` is responsible for running the compiled code $N$ times. You can run ``./run.sh <executable code> <csv file to save the results> <N>`` , e.g., ``./run.sh ibsecdsa ibsecdsa.csv 10000``.  Note that $N > 1$.
3. Finally, run the Python3 script as follows: ``python3 <csv file> <scheme>``. As an example: ``python3 ibsecdsa.csv ibsecdsa``.
