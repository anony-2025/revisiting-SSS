# Anonymous Submission Artifact

## Repository Overview

    .
    ├── ss-test.cpp
    ├── benchmark/
    ├── heuristic-bound/
    └── openfhe-development/

### 1. `ss-test.cpp`
Correctness checker for three secret sharing variants:
- Classic Shamir SSS
- BFM+25 SSS
- Refined SSS (**2adic**)

Run from the repository root:

    mkdir build && cd build
    cmake ..
    make -j
    ./ss-test

---

### 2. `openfhe-development/`
A **snapshot copy** of OpenFHE (not a submodule).

This snapshot includes:
- BFV-based Threshold FHE implementation  
- BFM+25 secret sharing  
- Refined (2adic) secret sharing  

To run the experiments, install **this** snapshot (not an external OpenFHE release):

    cd openfhe-development
    mkdir build && cd build
    cmake ..
    make -j
    sudo make install

---

### 3. `benchmark/`
Performance comparison code for:
- BGG+18  
- ThFHE with refined SSS  

Measures:
- Running time  
- Ciphertext / object sizes  

Build and run inside `benchmark/` using CMake in the usual way.

---

### 4. `heuristic-bound/`
Heuristic bound measurement code for:
- BFM+25  
- Refined (2adic) SSS  

Used to reproduce heuristic comparisons between the schemes.

---

## References

- **BGG+18**  
  D. Boneh, R. Gennaro, S. Goldfeder, A. Jain, S. Kim, P. Rasmussen and A. Sahai.  
  *Threshold Cryptosystems from Threshold Fully Homomorphic Encryption.*  
  Annual International Cryptology Conference (CRYPTO), 2018.

- **BFM+25**  
  Z. Brakerski, O. Friedman, A. Marmor, D. Mutzari, Y. Spiizer and N. Trieu.  
  *Threshold FHE with Efficient Asynchronous Decryption.*  
  Cryptology ePrint Archive, 2025.
