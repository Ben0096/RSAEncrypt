# RSAEncrypt

This code will allow you to encrypt files with RSA encryption by splitting them into chunks and encrypting those chunks.
It is still not recommended to attempt to encrypt very large files, as RSA is too slow for large files.

How to use
======================

cd into the build directory and then type:

```
cmake ..
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
