#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <math.h>
#include <cstring>
#include <string>
#include "BigInt.hpp"
#include <chrono>

using namespace std;
using namespace std::chrono;

void removeCharsFromString( string &str, char const * charsToRemove );
int hexToBigInt(string hex, BigInt& b);
int getFilesize(string filename);
string bigIntToBinaryString(BigInt& b);
int bitlength(BigInt& b);
int bytelength(BigInt& b);
string charToBinaryString(unsigned char b);
int bigIntToByteArray(BigInt& b, unsigned char* bytearray, int bytelength);
int byteArrayToBigInt(BigInt& b, unsigned char* bytearray, int bytelength);
BigInt modExpo(BigInt m, BigInt e, BigInt n);
BigInt modExpo(BigInt m, int e, BigInt n);

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

    b = 0;
    string hexDigits = "0123456789abcdef";
    int power = hex.length() - 1;
    BigInt powerOf16 = pow(BigInt(16), power);
    for (char const &c : hex) {
        if (int hexDigitValue = hexDigits.find(tolower(c)))
            b += powerOf16 * hexDigitValue;
        powerOf16 /= 16;
        // cout << c;
    }
    // cout << endl;
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
    string binstring = "";
    for (BigInt t = BigInt(b); t > 0; t /= 2) {
        if ((int)t.to_string().back() % 2) {
            binstring = "1" + binstring;
        } else {
            binstring = "0" + binstring;
        }
    }
    return binstring;
}

int bitlength(BigInt& b) {
    return bigIntToBinaryString(b).length();
}

int bytelength(BigInt& b) {
    int bitlen = bigIntToBinaryString(b).length();
    return (bitlen + 7) / 8;
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
        bytearray[i] = stoi(binstring.substr(len - 8), 0, 2);
        binstring = binstring.substr(0, len - 8);
    }
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

BigInt modExpo(BigInt m, BigInt e, BigInt n) {
    BigInt r = 1;
    while (1) {
        if (e % 2 == 1) {
            r = r * m % n;
        }
        e /= 2;
        if (e == 0) break;
        m = m * m % n;
    }
    return r;
}

void test();

void test() {

    // cout << "BigInt test\n";

    // int i = 69822547;
    // int j = 7;
    // int k = i^j;

    // cout << k << endl;

    // BigInt bigi = BigInt("4387593284795203459827304597230947592374059827349572384598634763846793485762938457");
    // BigInt bigj = BigInt(j);
    // BigInt bigk = pow(bigi, j);

    // cout << bigk << endl;
    
    // ofstream ofs ("test.txt", ofstream::out);

    // ofs << "lorem ipsum";
    // ofs << "morem ipsum" << endl;
    // ofs << "even morem ipsum" << endl;

    // ofs.close();

    // BigInt b = -600;

    // cout << b.sign << b.value << endl;

    // char c[] = "hey buddy 123456789 123 5678";

    // cout << sizeof(c) << endl;
    // cout << sizeof(&c) << endl;
    // cout << c << endl;

    // cout << pow(BigInt(2), 1024) << endl;

    // int asdf = stoi("11011011", 0, 2);

    // cout << "stoi(\"11011011\", 0, 2): " << asdf << endl;

    // cout << "\"01234\".substr(0, 3): " << string("01234").substr(0, 3) << endl;
    // cout << "\"01234\".substr(3): " << string("01234").substr(3) << endl;

    // cout << "charToBinaryString(64): " << charToBinaryString(64) << endl;
    // cout << "charToBinaryString(254): " << charToBinaryString(254) << endl;
    // cout << "charToBinaryString(188): " << charToBinaryString(188) << endl;
    // cout << "charToBinaryString(189): " << charToBinaryString(189) << endl;
    // cout << "charToBinaryString(15): " << charToBinaryString(15) << endl;

    // int size = bytelength(bigi);
    // unsigned char* ba = new unsigned char[size]();
    // bigIntToByteArray(bigi, ba, size);

    // // cout << "size of byte array: " << size << endl;
    // // cout << "byte array input: " << bigi << endl;
    // // for (int i = 0; i < size; i++) {
    // //     cout << "i: " << i << endl;
    // //     string s = charToBinaryString(ba[i]);
    // //     cout << s << endl;
    // // }
    // // cout << endl;
    
    // cout << "bigi: " << bigi << endl;
    // // int sizebigi = bytelength(bigi);
    // // unsigned char* keynarr = new unsigned char[sizebigi]();
    // // bigIntToByteArray(bigi, keynarr, sizebigi);
    // byteArrayToBigInt(bigi, ba, size);
    // cout << "bigi: " << bigi << endl;

    // // for (int i = 0; i < size; i++) {
    // //     cout << "i: " << i << endl;
    // //     string s = charToBinaryString(ba[i]);
    // //     cout << s << endl;
    // // }

    // size = bytelength(bigi);
    // unsigned char* ba2 = new unsigned char[size]();

    // BigInt m = string("1234567890123456789012345678901234567890123456789012345678901234567890");
    // BigInt e = string("12345678900987654321123456789009876543211234567890098765432112345678901234567890123456789012345678901234567890");
    // BigInt n = string("123456789012345678909087654321908765432112345678901234567890123456789012345678912345678901234567890123456789012345678901234567890");
    // BigInt m = string("123456789012390123456789012345678901234567890");
    // BigInt e = string("12345678900987654987655012345678923401234567890");
    // BigInt n = string("123456789012345678909087654321908765432112345678990");
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