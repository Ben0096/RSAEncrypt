#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <math.h>
#include <cstring>
#include <string>
// #include "BigInt.hpp"

#include "BigInteger.hpp"

typedef BigUnsigned BigInt;

using namespace std;

int findLastIndex(string& str, char x);
void removeCharsFromString( string &str, char const * charsToRemove );
int hexToBigInt(string hex, BigInt& b);
int getFilesize(string filename);
string bigIntToBinaryString(BigInt& b);
int bitlength(BigInt& b);
int bytelength(BigInt& b);
string charToBinaryString(unsigned char b);
int bigIntToByteArray(BigInt& b, unsigned char* bytearray, int bytelength);
int byteArrayToBigInt(BigInt& b, unsigned char* bytearray, int bytelength);
string byteArrayToBinaryString(unsigned char** bytearray, int first_block_size, int block_size, int num_blocks);

int findLastIndex(string& str, char x) 
{ 
    // Traverse from right 
    for (int i = str.length() - 1; i >= 0; i--) 
        if (str[i] == x) 
            return i; 
  
    return -1; 
} 

void removeCharsFromString( string &str, char const * charsToRemove ) {
    for ( unsigned int i = 0; i < strlen(charsToRemove); ++i ) {
        str.erase( remove(str.begin(), str.end(), charsToRemove[i]), str.end() );
    }
}

int hexToBigInt(string hex, BigInt& b) {
    // return 0 if there are any non-hexadecimal chars in this string
    string temp = hex;
    removeCharsFromString(temp, "0123456789ABCDEFabcdef");
    if (temp.length() > 0) return 0;

    b = BigUnsignedInABase(hex, 16);

    return 1;
}

/**
 * Returns the size in bytes of the file denoted by filename
 * 
 */
int getFilesize(string filename) {

    ifstream in;
    in.open(filename, ios::in|ios::binary);
    int first = in.tellg();
    in.seekg(0, ios::end);
    int last = in.tellg();
    in.close();
    return last - first;
}

string bigIntToBinaryString(BigInt& b) {
    string s = string(BigUnsignedInABase(b, 2));
    return s;
}

string bigIntToHexString(BigInt& b) {
    string s = string(BigUnsignedInABase(b, 16));
    return s;
}

string bigIntToB64String(BigInt& b) {
    BigUnsignedInABase bib = BigUnsignedInABase(b, 64);
    int base = 64;
    int len = bib.getLength();
    char* s = new char[len +1];
    s[len] = '\0';
    unsigned int digitNum, symbolNumInString;
    for (symbolNumInString = 0; symbolNumInString < len; symbolNumInString++) {
		digitNum = len - 1 - symbolNumInString;
		unsigned short theDigit = bib.getDigit(digitNum);
        if (theDigit < 26)
            s[symbolNumInString] = char('A' + theDigit);
        else if (theDigit < 52)
            s[symbolNumInString] = char('a' + theDigit - 26);
        else if (theDigit < 62)
            s[symbolNumInString] = char('0' + theDigit - 52);
        else if (theDigit == 62)
            s[symbolNumInString] = char('+');
        else if (theDigit == 63)
            s[symbolNumInString] = char('/');
	}
	std::string s2(s);
	delete [] s;
	return s2;
}

int bitlength(BigInt& b) {
    return b.bitLength();
}

int bytelength(BigInt& b) {
    return (bitlength(b) + 7) / 8;
}

string charToBinaryString(unsigned char b) {
    string binstring = "";
    for (int i = b, j = 0; i > 0 || j < 8; i /= 2, j++) {
        if (i % 2) {
            binstring = "1" + binstring;
        } else {
            binstring = "0" + binstring;
        }
    }
    return binstring;
}

/**
 * Creates a byte array in bytearray that represents/is equivalent to b. 
 * 
 * In bytearray, the most significant byte is in the first index, 
 * and the least significant byte in the last index.
 * 
 * Returns the size of bytearray.
 * 
 * This is how bigIntToByteArray should be called:
 * 
 * int size = bytelength(b);
 * unsigned char* bytearray = new unsigned char[size]();
 * bigIntToByteArray(b, bytearray, size);
 * 
 */ 
int bigIntToByteArray(BigInt& b, unsigned char* bytearray, int bytelength) {
    if (b == 0) return 0;
    string binstring = bigIntToBinaryString(b);
    for (int i = bytelength - 1; i > 0; i--){
        int len = binstring.length();
        if (len > 8) { // more than 8 digits left
            bytearray[i] = stoi(binstring.substr(len - 8), 0, 2);
            binstring = binstring.substr(0, len - 8);
        } else if (len > 0) {
            bytearray[i] = stoi(binstring, 0, 2);
            binstring = "";
        } else {
            bytearray[i] = 0;
        }
    }
    if (binstring.length() > 0)
        bytearray[0] = stoi(binstring, 0, 2);
    return bytelength;
}

/**
 * Copies the data in bytearray to BigInt b.
 * 
 * In bytearray, the most significant byte is in the first index, 
 * and the least significant byte in the last index.
 * 
 */ 
int byteArrayToBigInt(BigInt& b, unsigned char* bytearray, int bytelength) {
    b = 0;
    BigInt power = 1;
    for (int i = bytelength - 1; i >= 0; i--) {
        b += power * bytearray[i];
        power *= 256;
    }
    return bytelength;
}

string byteArrayToBinaryString(unsigned char** bytearray, int first_block_size, int block_size, int num_blocks) {
    string returnString = "";
    if (bytearray) {
        for (size_t i = 0; i < num_blocks; i++)
        {
            int count = i == 0 ? first_block_size : block_size;
            for (size_t j = 0; j < count; j++)
            {
                returnString += charToBinaryString(bytearray[i][j]) + " ";
            }
        }
    }
    return returnString;
}

void test();

void test() {

    // BigInt m = string("6122186887234693563485793847598324958276349587897497");
    // BigInt e = string("10798354783163997432287365823764593264598763483764569");
    // BigInt n = string("131982656512444442202983764598763548736546537478948654629");

    // milliseconds time1 = duration_cast< milliseconds >(
    //     system_clock::now().time_since_epoch()
    // );
    // for (size_t i = 0; i < 1; i++)
    // {
    //     modExpo(m,e,n);
    // }
    // milliseconds time2 = duration_cast< milliseconds >(
    //     system_clock::now().time_since_epoch()
    // );
    // for (size_t i = 0; i < 1; i++)
    // {
        
    // }
    // milliseconds time3 = duration_cast< milliseconds >(
    //     system_clock::now().time_since_epoch()
    // );
    // cout << "time1: " << (time2 - time1).count() << endl;
    // cout << "time2: " << (time3 - time2).count() << endl;
}