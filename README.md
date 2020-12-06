# RSAEncrypt

This code will allow you to encrypt files with RSA encryption by splitting them into chunks and encrypting those chunks.
It is still not recommended to attempt to encrypt very large files, as RSA is too slow for large files.

Dr B: how to test
======================

cd into the build directory and then type:

```
make
```

and then copy paste the following:

```
./rsa -t -k ../keys/1024_key_components.txt -f ../examplefiles/small_plaintext.txt 
```

This is what the output should look like: (the output file binary data should be different every time since the rsa process adds random data before encrypting):

```
=============== BEGINNING RSA ENCRYPTION ===============


Input file as text:
This is a small text file.

Input file as binary data:
01010100 01101000 01101001 01110011 00100000 01101001 01110011 00100000 01100001 00100000 01110011 01101101 01100001 01101100 01101100 00100000 01110100 01100101 01111000 01110100 00100000 01100110 01101001 01101100 01100101 00101110 

Output file (encrypted) as binary data:
11001001 00110100 01011011 00100000 11011000 00110111 01110110 10101001 11110011 00110010 00000001 11111001 11111100 01100000 01000110 00010011 01001010 01111100 10101111 10110111 11101100 11010100 11001111 11011000 11100011 00010100 00000000 00111101 00110011 11011010 01000001 00000101 10111100 01000000 00000010 00111011 01111011 11111110 01010100 01011001 10111001 01001000 11011001 10110100 10010000 00110110 01100101 00111111 10010100 11110010 10100001 01001101 00010010 01000001 10110000 11010000 01111110 11110110 01011010 00011111 11001110 11010100 11101011 10011001 00110101 01110111 00011101 11001010 10110110 01110010 10010000 01100000 10100011 00011000 01110110 11001111 11111010 01001010 00011010 11000100 11000111 00111111 10101101 10011010 00101000 10000111 10100101 10001100 00111000 10001100 00010010 10011101 01100100 10101001 00110010 01000010 00000001 00011101 01111101 11000100 00110100 10011001 00111101 00001001 11110110 00011010 10010000 01011010 00110110 01000100 00101010 11111000 01101001 00000011 01110010 11010011 10011011 10111001 10011010 01010001 01101100 01011011 00100111 10001111 10011110 00110011 00011010 11110000 


=============== BEGINNING RSA DECRYPTION ===============

Estimated decryption time: 0 seconds

Decrypted file as binary data: (should be the same as input file above)
01010100 01101000 01101001 01110011 00100000 01101001 01110011 00100000 01100001 00100000 01110011 01101101 01100001 01101100 01101100 00100000 01110100 01100101 01111000 01110100 00100000 01100110 01101001 01101100 01100101 00101110 

Decrypted file as text: (should be the same as input file above)
This is a small text file.



=============== RESULTS ===============

Time to encrypt: 28 milliseconds
Time to decrypt: 667 milliseconds

The result files, small_plaintext_encr.bin and small_plaintext_decr.txt can be found in the same directory as the original file.
```



How to use
======================

cd into the build directory and then type:

```
make
```

Note: the CMakeLists.txt file sets the compile flag `-std=c++11`.  If you plan to compile this project a different way, make sure this flag is set.

This should generate the executable called `rsa`.  You must provide 4 all arguments; encrypt or decrypt flag, an RSA key components file (more on that below), an input file, and an output file. For example:
```
rsa -e -k key_components.txt -f filename.ext -o outfilename.bin
```
This will encrypt filename.ext using the RSA key described in key_components.txt and save the result to outfilename.bin

Key components file?
======================

I have provided a few different RSA keys as well as their component files in the `keys` folder.  The reason for these "component" files is that they're much easier to read and parse than the plain .pem files.

To generate your own keys, you need [openssl](https://www.openssl.org/) [(github repo)](https://github.com/openssl/openssl).
Once you have that installed, you can type the commands:
```
openssl genrsa -out 1024_key.pem 1024
openssl -in 1024_key.pem -text -out 1024_key_components.txt
```

This will generate a 1024-bit RSA key and save it in 1024_key.pem.
Then the second line will save a more human-readable form into 1024_key_components.txt.

You can also generate just the public part:
```
openssl rsa -in 1024_key.pem -pubout -out 1024_key_public.pem
openssl rsa -pubin -in 1024_key_public.pem -text -out 1024_key_public_components.text
```
