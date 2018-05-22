# symmetric_encryption

By: Eric Fleith
November 2017

Simple algorithm that does symmetric encryption with key and IV of binary inputs in CBC, CTR, and ECB.

To compile and execute the file:

gcc cypher.c -o my-cypher

./my−cipher [ECB/CTR/CBC] [enc/dec] [rounds] [key] [plaintext (binary)] [IV - (if decrypting only)]

* if decrypting, you need to use the same IV as the one that was randomly generated during encryption.

* CTR is able to handle any number of bits greater than 12.

* key must be 9 bits/digits long

* only input binary numbers

Other observations:
- The pseudo random number generator used isn't optimized and is not recomended for real world security measurements.
- This code is a simple application meant for studying and understanding symmetric encryption
