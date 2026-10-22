# On the use of ECDSA with hierarchical public key delegation in identity-based scenarios

> Lucas C. Cardoso and Marcos A. Simplicio Jr. IACR Communications in Cryptology 2026, Issue 3.

**Abstract**. This repository contains the code associated with our paper "On the use of ECDSA with hierarchical public key delegation in identity-based scenarios", IACR Communications in Cryptology 2026, Issue 3. Our implementation contains 3 main components: (i) the LaTeX source code with the authorship anonymized, (ii) the implementation of the schemes discussed in the paper with OpenSSL, and (iii) a Python script to analyze the results.

## Directories

```
.
├── README.md
├── src
│   ├── Makefile
│   ├── analyse.py
│   ├── common.c
│   ├── common.h
│   ├── common.o
│   ├── ecdsa.c
│   ├── experiments
│   ├── ibsecdsa.c
│   ├── ibsecdsa.h
│   ├── ibsecdsa.o
│   ├── ibsecdsav1.c
│   ├── ibsecdsav2.c
│   ├── ibsecdsav3.c
│   ├── ibsschnorr.c
│   ├── ibsschnorr.h
│   ├── ibsschnorr.o
│   ├── main-ecdsa.c
│   ├── main-schnorr.c
│   ├── schnorr.c
│   ├── utils.c
│   ├── utils.h
│   └── utils.o
```

Each directory is described as follows:

1. src/: source code for the complete proof of concept.
2. src/experiments: .csv files for each benchmark.

## Requirements

We use the following packages to run our proof of concept:

1. OpenSSL v3.5.0: code written in C
2. gcc v14.2.0: compiler for C code
3. Python v3.13.2: scripts for performance analysis
4. Numpy v2.2.4: numerical calculation
5. CSV v1.0: csv file handling
We are using a common off-the-shelf equipment (Intel i7-6500U CPU @2.50GHz) to run the experiments.

## Running the code

We store the .csv files containing the results of each scheme inside the ``experiments/`` directory.
If no directory with this name exists, then the first step is not necessary and you can jump to the
``make libraries && make all`` instructions. The step-by-step is written as follows:

1. To run the C code, run the following command:

```
    make clean
```

Followed by:

```
    make libraries && make all
```

If it is desired to analyse the ``-O3`` variant of the code, run

```
    make optimized
```

As we discuss in the manuscript, using the ``-O3`` flag with the gcc compiler does not significantly alter the obtained results (which are done with the ``-O2``).

1. Then, run each benchmark with

```
    make run_bench
```

We make a total of $N = 10000$ experiments, being $10\\%$ dedicated to warm-up, to obtain the numerical values presented in the article.

1. Finally, to extract the statistics of the produced .csv file containing the NIST safe elliptic curve and the scheme, use the Python3 script and run the following command: ``python3 analyse.py -h``. Do not forget to create a python environment and install both ``numpy`` and ``csv``. The command template is as follows: ``python3 analyse.py <path to .csv file> <considered scheme: ds or ibs>``. We consider the ``brainpoolPXr1``, with $X \in \{224, 256, 320, 384, 512\}$, ``secpXr1``, with $X \in \{224, 384, 521\}$, and bitcoin curve ``secp256k1`` to conduct our experiments for the sake of completeness. In the paper, however, we consider only the ``secp`` curves with security levels $\lambda \in \{128, 192, 256\}$.
