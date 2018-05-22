# symmetric_encryption
Simple algorithm that does symmetric encryption with key and IV of binary inputs in CBC, CTR, and ECB.

To compile and execute the file:

gcc lab3.c -o my-cypher

./my−cipher [ECB/CTR/CBC] [enc/dec] [rounds] [key] [plaintext (binary)] [IV - (if decrypting only)]

if decrypting, you need to use the same IV as the one that was randomly generated during encryption.

CTR is able to handle any number of bits greater than 12.

key must be 9 bits/digits long

only input binary numbers
