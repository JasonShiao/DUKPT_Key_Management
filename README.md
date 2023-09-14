# DUKPT Key Management
  * Practice DES and TDES implementation  
  * Practice DUKPT implementation  
  * Currently only ANSI X9.24-3-2009 is implemented
  * TODO: Support ANSI X9.24-3-2017 AES DUKPT
  * Run from initial key loading until the end of life of dukpt (1048573 number of keys)
  
# CMake build
cmake -S . -B build
cmake --build build

# Run
./build/DUKPT

