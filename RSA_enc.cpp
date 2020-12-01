#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cmath>
#include <string>
#include <cstring>
#include <ctime>
#include "helpers.cpp"
#include <algorithm>

using namespace std;

class RSAKey {
    public:
    BigInt n; //modulus
    BigInt e; //publicExponent
    BigInt d; //privateExponent
    BigInt p; //prime1
    BigInt q; //prime2
    BigInt dmp1; //exponent1
    BigInt dmq1; //exponent2
    BigInt coeff; //coefficient
    RSAKey(){
        n = 0; //modulus
        e = 0; //publicExponent
        d = 0; //privateExponent
        p = 0; //prime1
        q = 0; //prime2
        dmp1 = 0;  //exponent1
        dmq1 = 0;  //exponent2
        coeff = 0; //coefficient
    }
};

RSAKey key;

bool encrypt = false;
bool decrypt = false;

/**
 * This is the size, in bytes, that chunks of ciphertext will be split
 * into to be processed.
 * 
 * This value depends on, and is equal to, the size in bytes of the
 * modulus of the key that is used for encryption and decryption.
 * 
 * 128 is the size when using 1024-bit excryption
 */
int CIPHER_CHUNK_SIZE = 128;
/**
 * This is the maximum size, in bytes, that chunks of data (plaintext)
 * can split into in order to be used in RSA encryption.
 *  
 * 117 bytes per encryption chunk is the MAX_PLAIN_CHUNK_SIZE for a
 * key.n_size of 128.  (1024 bit)
 * 
 * In general, this value is equal to (CIPHER_CHUNK_SIZE - 11). This allows
 * for at least 8 bytes of random pad (and 3 bytes of padding markers)
 * to be added during encryption.
 */
int MAX_PLAIN_CHUNK_SIZE = 117;
/**
 * Message size in bytes.  This will be the size of the entire plaintext
 * file.
 * 
 * todo: make sure this is properly set in the decryption flow
 */
int messagesize = 0;
/**
 * The first chunk of bytes that the plaintext is split into will likely
 * be less than MAX_PLAIN_CHUNK_SIZE bytes.  This is the size in bytes
 * of that first chunk.
 */
int first_chunk_size = 0;
/**
 * The size of the array of the plaintext separated into chunks.
 * 
 * This is the number of chunks of size MAX_PLAIN_CHUNK_SIZE (with the first
 * chunk being of sizefirst_chunk_size) that the message (plaintext) will
 * be split into in order to apply the RSA encryption.
 */
int plaintext_array_size = 0;
unsigned char** plaintext_array = nullptr;
int padtext_array_size = 0;
unsigned char** padtext_array = nullptr;
BigInt* padtext_array_b = nullptr;
int ciphertext_array_size = 0;
BigInt* ciphertext_array_b = nullptr;
unsigned char** ciphertext_array = nullptr;

int readRSAKeyComponentsFile(string filename, RSAKey& key);
string readNextHexValue(ifstream &in, string &line);
int pkcs1pad2(int n_modulus_bytelength, int chunk_size, int index);
int pkcs1unpad2(int n_modulus_bytelength, int* chunk_size, int index);
void printMessageArrays();

/**
 * Should receive a line of the form:
 * 
 * "publicExponent: 65537 (0x10001)"
 * 
 * and return a line of the form:
 * 
 * "65537"
 */
string extractPublicExponent(string line) {
    line = line.substr(16);
    int t = line.find(" (");
    if (t != string::npos) line = line.substr(0,t);
    return line;
}

/**
 * Reads in the given RSA Key components file and returns a new RSAKey
 * that represents that file.
 * 
 * If the file is not in the exact expected format a nullptr will be returned
 * 
 * The RSA Key components file for the private key can be obtained with
 * OpenSSL with the following terminal commands:
 * 
 * openssl genrsa -out rsa_priv.pem 1024
 * 
 * openssl rsa -in key.pem -text -out rsa_priv_components.txt
 * 
 * 
 * The RSA Key components file for the public key can be obtained with
 * OpenSSL with the following terminal commands:
 * 
 * openssl rsa -in rsa_priv.pem -pubout -out rsa_pub.pem
 * 
 * openssl rsa -pubin -in rsa_pub.pem -text -out rsa_pub_components.text
 * 
 * @param filename  the name of the file to read from
 * @param key  the RSAKey to model after the file
 * @return  1 if successful, 0 if unsuccessful
 */
int readRSAKeyComponentsFile(string filename, RSAKey& key) {
    string valueBeingReadIn;

    ifstream in;
    in.open(filename);
    string line;

    getline(in, line); // "Private-Key: (1024 bit)"
    getline(in, line); // "modulus:"
    if (strcmp(line.substr(0,8).c_str(), "modulus:") == 0) {
        string hexVal = readNextHexValue(in, line);
        if (!hexToBigInt(hexVal, key.n)) return 0;
    } else return 0;
    
cout << "Before publicExponent: " << line << endl;
    if (strcmp(line.substr(0,15).c_str(), "publicExponent:") == 0) {
        key.e = extractPublicExponent(line);
    } else return 0;
cout << key.e << endl;
    getline(in, line);
    if (strcmp(line.substr(0,16).c_str(), "privateExponent:") == 0) {
        string hexVal = readNextHexValue(in, line);
        if (!hexToBigInt(hexVal, key.d)) return 0;
    } else return 0;

    if (strcmp(line.substr(0,7).c_str(), "prime1:") == 0) {
        string hexVal = readNextHexValue(in, line);
        if (!hexToBigInt(hexVal, key.p)) return 0;
    } else return 0;

    if (strcmp(line.substr(0,7).c_str(), "prime2:") == 0) {
        string hexVal = readNextHexValue(in, line);
        if (!hexToBigInt(hexVal, key.q)) return 0;
    } else return 0;

    if (strcmp(line.substr(0,10).c_str(), "exponent1:") == 0) {
        string hexVal = readNextHexValue(in, line);
        if (!hexToBigInt(hexVal, key.dmp1)) return 0;
    } else return 0;

    if (strcmp(line.substr(0,10).c_str(), "exponent2:") == 0) {
        string hexVal = readNextHexValue(in, line);
        if (!hexToBigInt(hexVal, key.dmq1)) return 0;
    } else return 0;

    if (strcmp(line.substr(0,12).c_str(), "coefficient:") == 0) {
        string hexVal = readNextHexValue(in, line);
        if (!hexToBigInt(hexVal, key.coeff)) return 0;
    } else return 0;

    // while (getline(in, line)){
    //     cout << line << endl;
    // }
    in.close();
    return 1;
}

string readNextHexValue(ifstream &in, string &line) {
    string valueBeingReadIn = "";
    while (getline(in, line)) {
        // lines containing 15 hex values separated by : and indented
        // with 4 spaces are 49 characters long
        if (line.length() == 49) {
            valueBeingReadIn += line;
        } 
        // if it's not 49 chars long, it's either the last line of hex values
        // or it's the header for the next section.
        // 4 leading spaces means it's the last line of hex values.
        else if (strcmp(line.substr(0,4).c_str(), "    ") == 0) {
            valueBeingReadIn += line;
        } else {
            break;
        }
    }
    removeCharsFromString(valueBeingReadIn, ": ");
    return valueBeingReadIn;
}

int readInputFile(string filename){
    ifstream in;
    in.open(filename, ios::in | ios::binary);
    for (size_t i = 0; i < plaintext_array_size; i++) {
        int chunk_size = (i == 0) ? messagesize % MAX_PLAIN_CHUNK_SIZE : MAX_PLAIN_CHUNK_SIZE;
        for (size_t j = 0; j < chunk_size; j++) {
            in.read((char*)&plaintext_array[i][j], sizeof(unsigned char));
        }
    }
    in.close();
    return 1;
}

/**
 * Gets binary info from file and stores it in global plaintext_array.
 * 
 * Sets plaintext_array_size to the appropriate size.
 */ 
int getPlaintextFromFile(string filename) {
    messagesize = getFilesize(filename);
    if (!messagesize || key.n == 0) return 0;
    plaintext_array_size = (messagesize + MAX_PLAIN_CHUNK_SIZE - 1) / MAX_PLAIN_CHUNK_SIZE;
    first_chunk_size = messagesize % MAX_PLAIN_CHUNK_SIZE;
    plaintext_array = new unsigned char*[plaintext_array_size]();
    for (size_t i = 0; i < plaintext_array_size; i++) {
        int chunk_size;
        if (i == 0) {
            chunk_size = first_chunk_size;
        } else {
            chunk_size = MAX_PLAIN_CHUNK_SIZE;
        }
        plaintext_array[i] = new unsigned char[chunk_size]();
    }

    readInputFile(filename);

    return 1;
}

int shoveMessageIntoByteArray(string msg) {
    for (size_t i = 0; i < plaintext_array_size; i++) {
        int count = i == 0 ? first_chunk_size : MAX_PLAIN_CHUNK_SIZE;
        for (size_t j = 0; j < count; j++) {
            plaintext_array[i][j] = (unsigned char) msg.at((i == 0) ? j : j + first_chunk_size + (i - 1) * MAX_PLAIN_CHUNK_SIZE);
        }
    }
    return 1;
}

int getPlaintextFromMessage(string msg) {
    messagesize = msg.length();
    if (!messagesize || key.n == 0) return 0;
    plaintext_array_size = (messagesize + MAX_PLAIN_CHUNK_SIZE - 1) / MAX_PLAIN_CHUNK_SIZE;
    first_chunk_size = messagesize % MAX_PLAIN_CHUNK_SIZE;
    plaintext_array = new unsigned char*[plaintext_array_size]();
    for (size_t i = 0; i < plaintext_array_size; i++) {
        int chunk_size;
        if (i == 0) {
            chunk_size = first_chunk_size;
        } else {
            chunk_size = MAX_PLAIN_CHUNK_SIZE;
        }
        plaintext_array[i] = new unsigned char[chunk_size]();
    }

    shoveMessageIntoByteArray(msg);

    return 1;
}

int padPlaintext() {
    padtext_array_size = plaintext_array_size;
    
    padtext_array = new unsigned char*[padtext_array_size]();
    for (size_t i = 0; i < plaintext_array_size; i++) {
        int chunk_size = (i == 0) ? messagesize % MAX_PLAIN_CHUNK_SIZE : MAX_PLAIN_CHUNK_SIZE;
        pkcs1pad2(128, chunk_size, i);
    }
    padtext_array_b = new BigInt[padtext_array_size]();
    for (size_t i = 0; i < padtext_array_size; i++) {
        byteArrayToBigInt(padtext_array_b[i], padtext_array[i], 128);
    }
    return 1;
}

int modExpoPadtext() {
    ciphertext_array_size = padtext_array_size;
    ciphertext_array_b = new BigInt[padtext_array_size]();
    for (size_t i = 0; i < ciphertext_array_size; i++) {
        ciphertext_array_b[i] = modExpo(padtext_array_b[i], key.e, key.n);
    }
    ciphertext_array = new unsigned char*[ciphertext_array_size]();
    for (size_t i = 0; i < ciphertext_array_size; i++)
    {
        ciphertext_array[i] = new unsigned char[128]();
        bigIntToByteArray(ciphertext_array_b[i], ciphertext_array[i], 128);
    }
    
    return 1;
}

int writeCipherToFile(string outfile) {
    ofstream out;
    out.open(outfile, ios::out | ios::binary);
    for (size_t i = 0; i < ciphertext_array_size; i++)
    {
        for (size_t j = 0; j < 128; j++)
        {
            out.put(ciphertext_array[i][j]);
        }
    }
    out.close();
    return 1;
}

int encryptFile(string filename, string outfile) {
    cout << "encryptFile -----------" << endl;
    getPlaintextFromFile(filename);
    padPlaintext();
    modExpoPadtext();
    writeCipherToFile(outfile);
    return 1;
}

int readCipherFile(string filename){
    ifstream in;
    in.open(filename, ios::in | ios::binary);
    for (size_t i = 0; i < ciphertext_array_size; i++) {
        int chunk_size = 128;
        for (size_t j = 0; j < chunk_size; j++) {
            in.read((char*)&ciphertext_array[i][j], sizeof(unsigned char));
        }
    }
    in.close();
    return 1;
}

/**
 * Gets binary info from file and stores it in global ciphertext_array.
 * 
 * Sets ciphertext_array_size to the appropriate size.
 */ 
int getCiphertextFromFile(string filename) {
    messagesize = getFilesize(filename);
    if (!messagesize || key.n == 0) return 0;
    ciphertext_array_size = messagesize / 128; // ciphertext must always be a multiple of 128 bytes in size for 1024 bit keys
    ciphertext_array = new unsigned char*[ciphertext_array_size]();
    for (size_t i = 0; i < ciphertext_array_size; i++) {
        ciphertext_array[i] = new unsigned char[128]();
    }

    readCipherFile(filename);

    return 1;
}

int modExpoCiphertext() {
    
    ciphertext_array_b = new BigInt[ciphertext_array_size]();
    for (size_t i = 0; i < ciphertext_array_size; i++)
    {
        byteArrayToBigInt(ciphertext_array_b[i], ciphertext_array[i], 128);
    }

    padtext_array_size = ciphertext_array_size;
    padtext_array_b = new BigInt[ciphertext_array_size]();
    for (size_t i = 0; i < padtext_array_size; i++) {
        padtext_array_b[i] = modExpo(ciphertext_array_b[i], key.d, key.n);
    }

    return 1;
}

int unpadPadtext() {
    padtext_array = new unsigned char*[padtext_array_size]();
    for (size_t i = 0; i < padtext_array_size; i++)
    {
        padtext_array[i] = new unsigned char[128]();
        bigIntToByteArray(padtext_array_b[i], padtext_array[i], 128);
    }

    plaintext_array_size = padtext_array_size;

    for (size_t i = 0; i < padtext_array_size; i++) {
        int chunk_size = 0;
        pkcs1unpad2(128, &chunk_size, i);
        if (i == 0) first_chunk_size = chunk_size;
    }
    return 1;
}

int writePlaintextToFile(string outfile) {
    ofstream out;
    out.open(outfile, ios::out | ios::binary);
    for (size_t i = 0; i < plaintext_array_size; i++)
    {
        int count = i == 0 ? first_chunk_size : MAX_PLAIN_CHUNK_SIZE;
        for (size_t j = 0; j < count; j++)
        {
            out.put(plaintext_array[i][j]);
        }
    }
    out.close();
    return 1;
}

int decryptFile(string filename, string outfile) {
    cout << "decryptFile -----------" << endl;
    getCiphertextFromFile(filename);
printMessageArrays();
    modExpoCiphertext();
printMessageArrays();
    unpadPadtext();
    writePlaintextToFile(outfile);
    return 1;
}

// pkcs1pad2 (plaintext, #bytes in key.n)
int pkcs1pad2(int n_modulus_bytelength, int chunk_size, int index) {
    if(n_modulus_bytelength < chunk_size + 11) {
        return 0; // error, plaintext chunk is too large or key.n is too small
    }
    padtext_array[index] = new unsigned char[n_modulus_bytelength]();
    int i = chunk_size - 1;
    int n = n_modulus_bytelength;
    while (i >= 0 && n > 0) {
        unsigned char c = plaintext_array[index][i--];
        padtext_array[index][--n] = c;
    }
    padtext_array[index][--n] = 0;
    // srand(time(0));  //todo uncomment this line
    while (n > 2) {
        unsigned char c;
        while ((c = rand()) == 0){}
        padtext_array[index][--n] = c;
    }
    padtext_array[index][--n] = 2;
    padtext_array[index][--n] = 0;
    // delete[] plaintext;
    // return bytearray;
    return 1;
}

// pkcs1unpad2 (plaintext, #bytes in key.n)
int pkcs1unpad2(int n_modulus_bytelength, int* chunk_size, int index) {
    
    int i = 0;
    while (i < n_modulus_bytelength && padtext_array[index][i] == 0) {
        i++;
    }
    if (i != 1 || padtext_array[index][i] != 2) {
        return 0;
    }
    ++i;
    while (padtext_array[index][i] != 0) {
        if (++i >= n_modulus_bytelength) return 0;
    }

    int plaintext_start_index = i + 1; // 118
    *chunk_size = n_modulus_bytelength - plaintext_start_index;
    // unsigned char* plaintext = new unsigned char[*chunk_size]();
        // 118
    plaintext_array[index] = new unsigned char[n_modulus_bytelength + 1 - plaintext_start_index]();
    while (++i < n_modulus_bytelength) {
        plaintext_array[index][i - plaintext_start_index] = padtext_array[index][i];
    }
    // delete[] padtext;
    // *padtext_array[index] = *plaintext_array[index];
    return 1;
}

void printMessageArrays() {
    cout << "plaintext_array_size " << plaintext_array_size << endl;
    if (plaintext_array_size && first_chunk_size) {
        cout << "plaintext_array:" << endl; 
        for (size_t i = 0; i < plaintext_array_size; i++)
        {
            int count = i == 0 ? first_chunk_size : MAX_PLAIN_CHUNK_SIZE;
            for (size_t j = 0; j < count; j++)
            {
                cout << charToBinaryString(plaintext_array[i][j]) << " ";
            }
            cout << endl;
        }
    }
    if (padtext_array_size) {
        cout << "padtext_array:" << endl; 
        for (size_t i = 0; i < padtext_array_size; i++)
        {
            int count = 128;
            for (size_t j = 0; j < count; j++)
            {
                cout << "";
                cout << charToBinaryString(padtext_array[i][j]) << " ";
            }
            cout << endl;
        }
    }
    if (padtext_array_b && padtext_array_b[0] != 0) {
        cout << "padtext_array_b:" << endl; 
        for (size_t i = 0; i < padtext_array_size; i++)
        {
            cout << padtext_array_b[i] << endl;;
        }
    }
    if (ciphertext_array_b && ciphertext_array_b[0] != 0) {
        cout << "ciphertext_array_b:" << endl; 
        for (size_t i = 0; i < ciphertext_array_size; i++)
        {
            cout << ciphertext_array_b[i] << endl;;
        }
    }
    if (ciphertext_array_size) {
        cout << "ciphertext_array:" << endl; 
        for (size_t i = 0; i < ciphertext_array_size; i++)
        {
            int count = 128;
            for (size_t j = 0; j < count; j++)
            {
                cout << charToBinaryString(ciphertext_array[i][j]) << " ";
            }
            cout << endl;
        }
    }
}

void printInvalidArguments() {
    cout << "ERROR\nYou must provide all arguments for example:\n"
    << "rsa -e -k key_components.txt -f filename.ext -o outfilename.ext\n\n";
}

void test2() {
    string s = "publicExponent: 65537 (0x10001)";
    s = extractPublicExponent(s);
    cout << "\"" << s << "\"" << endl;
}

/**
 * rsa -- encrypt or decrypt a file or message using rsa
 * 
 * rsa [-e | -d] [-k] private_key_file [-i] infile [-im] "message to encrypt" [-o] outfile 
 * 
 * -e   Encrypt the input
 * 
 * -d   Decrypt the input
 * 
 **/ 
int main(int argc, char** argv) {
    if (argc < 8) {
        test2();
        printInvalidArguments();
        return 0;
    }
    if (strcmp(argv[1], "-e") == 0) {
        encrypt = true;
    } else if (strcmp(argv[1], "-d") == 0) {
        decrypt = true;
    } else {
        printInvalidArguments();
        return 0;
    }
    if (strcmp(argv[2], "-k") == 0 &&
        strcmp(argv[4], "-f") == 0 &&
        strcmp(argv[6], "-o") == 0) {
            readRSAKeyComponentsFile(argv[3], key);
            if (encrypt) encryptFile(argv[5], argv[7]);
            else if (decrypt) decryptFile(argv[5], argv[7]);
    } else {
        printInvalidArguments();
        return 0;
    }

    printMessageArrays();

    return 1;
}