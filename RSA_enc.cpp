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

string ERROR_MSG = "ERROR\n";

class RSAKey {
    public:
    BigUnsigned n; //modulus
    BigUnsigned e; //publicExponent
    BigUnsigned d; //privateExponent
    BigUnsigned p; //prime1
    BigUnsigned q; //prime2
    BigUnsigned dmp1; //exponent1
    BigUnsigned dmq1; //exponent2
    BigUnsigned coeff; //coefficient
    /**
     * Default constructor
     */
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
 * This is the size, in bytes, that blocks of ciphertext will be split
 * into to be processed.
 * 
 * This value depends on, and is equal to, the size in bytes of the
 * modulus of the key that is used for encryption and decryption.
 * 
 * 128 is the size when using 1024-bit encryption key
 */
int CIPHER_BLOCK_SIZE = 128;
/**
 * The minimum amount of padding to add to plaintext blocks before
 * encrypting them.  The amount of random bytes added is equal to
 * MIN_PAD - 3.
 * 
 * PKCS#1 reccommends a value of at least 11.
 */
int MIN_PAD = 11;
/**
 * This is the maximum size, in bytes, that blocks of data (plaintext)
 * can split into in order to be used in RSA encryption.
 *  
 * 117 bytes per encryption block is the MAX_PLAIN_BLOCK_SIZE for a
 * key.n size of 128.  (1024 bit)
 * 
 * In general, this value is equal to (CIPHER_BLOCK_SIZE - 11). This allows
 * for at least 8 bytes of random pad (and 3 bytes of padding markers)
 * to be added during encryption.
 */
int MAX_PLAIN_BLOCK_SIZE = 117;
/**
 * Message size in bytes.  This will be the size of the entire plaintext
 * file.
 */
int MESSAGE_SIZE = 0;
/**
 * The first block of bytes that the plaintext is split into will likely
 * be less than MAX_PLAIN_BLOCK_SIZE bytes.  This is the size in bytes
 * of that first block.
 */
int FIRST_BLOCK_SIZE = 0;
/**
 * The size for the arrays that will hold the plaintext, padded plaintext, and ciphertext.
 * 
 * This is the number of blocks that the message will be split into
 * in order to perform the encryption and decryption.
 */
int MSG_ARRAY_SIZE = 0;
unsigned char** plaintext_array = nullptr;
unsigned char** padtext_array = nullptr;
BigUnsigned* padtext_array_b = nullptr;
BigUnsigned* ciphertext_array_b = nullptr;
unsigned char** ciphertext_array = nullptr;

int readRSAKeyComponentsFile(string filename, RSAKey& key);
string readNextHexValue(ifstream &in, string &line);
int pkcs1pad2(int padded_msg_size, int msg_size, int index);
int pkcs1unpad2(int padded_msg_size, int* msg_size, int index);
void printMessageArrays();
void printPlaintextArray(int print_title = 0);
void printPlaintextArrayAsHex(int print_title = 0);
void printPlaintextArrayAsText(int print_title = 0);
void printPadtextArray(int print_title = 0);
void printPadtextArrayB(int print_title = 0);
void printCiphertextArrayB(int print_title = 0);
void printCiphertextArray(int print_title = 0);
void ERROR(string err_msg = "");

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
    line = line.substr(line.find(": ") + 2);
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
 * @return  1 if successful, 0 if unsuccessful
 */
int readRSAKeyComponentsFile(string filename) {

    ifstream in;
    in.open(filename);
    string line;

    getline(in, line); // "Private-Key: (1024 bit)"
    getline(in, line); // "modulus:"
    if (line.find("odulus:") != string::npos) {
        string hexVal = readNextHexValue(in, line);
        if (!hexToBigInt(hexVal, key.n)) return 0;
        CIPHER_BLOCK_SIZE = bytelength(key.n);
        if (CIPHER_BLOCK_SIZE < 16) {
            ERROR("ERROR: please provide an RSA key that's 128 bits or larger.\n");
            return 0;
        }
        MAX_PLAIN_BLOCK_SIZE = CIPHER_BLOCK_SIZE - MIN_PAD;
    } else return 0;
    
    if (line.find("xponent:") != string::npos) {
        key.e = stringToBigUnsigned(extractPublicExponent(line));
    } else return 0;
    
    if (decrypt) {
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
    }
    // just write the contents of the file to console
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
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        int block_size = (i == 0) ? FIRST_BLOCK_SIZE : MAX_PLAIN_BLOCK_SIZE;
        in.read((char*)plaintext_array[i], sizeof(unsigned char) * block_size);
    }
    in.close();
    return 1;
}

/**
 * Gets binary info from file and stores it in global plaintext_array.
 * 
 * Sets MESSAGE_SIZE
 * Sets MSG_ARRAY_SIZE
 * Sets FIRST_BLOCK_SIZE
 * 
 * Initializes plaintext_array and fills it with values from the file given by filename
 */ 
int getPlaintextFromFile(string filename) {
    // set global variables that are based on file size
    MESSAGE_SIZE = getFilesize(filename);
    if (!MESSAGE_SIZE || key.n == 0) return 0;
    MSG_ARRAY_SIZE = (MESSAGE_SIZE + MAX_PLAIN_BLOCK_SIZE - 1) / MAX_PLAIN_BLOCK_SIZE;
    FIRST_BLOCK_SIZE = MESSAGE_SIZE % MAX_PLAIN_BLOCK_SIZE;
    if (FIRST_BLOCK_SIZE == 0) FIRST_BLOCK_SIZE = MAX_PLAIN_BLOCK_SIZE;
    // initialize plaintext_array
    plaintext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        int block_size;
        if (i == 0) {
            block_size = FIRST_BLOCK_SIZE;
        } else {
            block_size = MAX_PLAIN_BLOCK_SIZE;
        }
        plaintext_array[i] = new unsigned char[block_size]();
    }
    // fill plaintext_array with contents from file
    readInputFile(filename);

    return 1;
}

int padPlaintext() {

    padtext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        int block_size = (i == 0) ? FIRST_BLOCK_SIZE : MAX_PLAIN_BLOCK_SIZE;
        pkcs1pad2(CIPHER_BLOCK_SIZE, block_size, i);
    }
    padtext_array_b = new BigUnsigned[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        byteArrayToBigInt(padtext_array_b[i], padtext_array[i], CIPHER_BLOCK_SIZE);
    }
    return 1;
}

int modExpoPadtext() {
    
    ciphertext_array_b = new BigUnsigned[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        ciphertext_array_b[i] = modexp(padtext_array_b[i], key.e, key.n);
    }
    ciphertext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        ciphertext_array[i] = new unsigned char[CIPHER_BLOCK_SIZE]();
        bigIntToByteArray(ciphertext_array_b[i], ciphertext_array[i], CIPHER_BLOCK_SIZE);
    }
    return 1;
}

int writeCipherToFile(string outfile) {
    ofstream out;
    out.open(outfile, ios::out | ios::binary);
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        for (size_t j = 0; j < CIPHER_BLOCK_SIZE; j++)
        {
            out.put(ciphertext_array[i][j]);
        }
    }
    out.close();
    return 1;
}

int encryptFile(string filename, string outfile) {
    getPlaintextFromFile(filename);
    padPlaintext();
    modExpoPadtext();
    writeCipherToFile(outfile);
    return 1;
}

int readCipherFile(string filename){
    ifstream in;
    in.open(filename, ios::in | ios::binary);
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        in.read((char*)ciphertext_array[i], sizeof(unsigned char) * CIPHER_BLOCK_SIZE);
    }
    in.close();
    return 1;
}

/**
 * Gets binary info from file and stores it in global ciphertext_array.
 * 
 * Sets MSG_ARRAY_SIZE to the appropriate size.
 */ 
int getCiphertextFromFile(string filename) {
    MESSAGE_SIZE = getFilesize(filename);
    if (!MESSAGE_SIZE || key.n == 0) return 0;
    MSG_ARRAY_SIZE = MESSAGE_SIZE / CIPHER_BLOCK_SIZE;
    ciphertext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        ciphertext_array[i] = new unsigned char[CIPHER_BLOCK_SIZE]();
    }

    readCipherFile(filename);

    return 1;
}

int modExpoCiphertext() {
    
    ciphertext_array_b = new BigUnsigned[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        byteArrayToBigInt(ciphertext_array_b[i], ciphertext_array[i], CIPHER_BLOCK_SIZE);
    }
    
    padtext_array_b = new BigUnsigned[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        padtext_array_b[i] = modexp(ciphertext_array_b[i], key.d, key.n);
    }

    return 1;
}

int unpadPadtext() {
    // convert padtext_array_b to padtext_array
    padtext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        padtext_array[i] = new unsigned char[CIPHER_BLOCK_SIZE]();
        bigIntToByteArray(padtext_array_b[i], padtext_array[i], CIPHER_BLOCK_SIZE);
    }
    // unpad padtext_array and put results into plaintext_array
    plaintext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        int block_size = 0;
        pkcs1unpad2(CIPHER_BLOCK_SIZE, &block_size, i);
        if (i == 0) FIRST_BLOCK_SIZE = block_size;
    }
    return 1;
}

int writePlaintextToFile(string outfile) {
    ofstream out;
    out.open(outfile, ios::out | ios::binary);
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        int count = i == 0 ? FIRST_BLOCK_SIZE : MAX_PLAIN_BLOCK_SIZE;
        for (size_t j = 0; j < count; j++)
        {
            out.put(plaintext_array[i][j]);
        }
    }
    out.close();
    return 1;
}

int decryptFile(string filename, string outfile) {
    getCiphertextFromFile(filename);
    cout << "Estimated decryption time: " << (int)(.005235 * MSG_ARRAY_SIZE * CIPHER_BLOCK_SIZE)
        << " seconds\n";
    modExpoCiphertext();
    unpadPadtext();
    writePlaintextToFile(outfile);
    return 1;
}

int pkcs1pad2(int padded_msg_size, int msg_size, int index) {
    if(padded_msg_size < msg_size + MIN_PAD) {
        ERROR("msg_size input to pkcs1pad2 was too large\n");
    }
    padtext_array[index] = new unsigned char[padded_msg_size]();
    int i = msg_size - 1;
    int n = padded_msg_size;
    while (i >= 0 && n > 0) {
        unsigned char c = plaintext_array[index][i--];
        padtext_array[index][--n] = c;
    }
    padtext_array[index][--n] = 0;
    srand(time(0));
    while (n > 2) {
        unsigned char c;
        while ((c = rand()) == 0){}
        padtext_array[index][--n] = c;
    }
    padtext_array[index][--n] = 2;
    padtext_array[index][--n] = 0;
    return 1;
}

int pkcs1unpad2(int padded_msg_size, int* msg_size, int index) {
    
    int i = 0;
    while (i < padded_msg_size && padtext_array[index][i] == 0) {
        i++;
    }
    if (i != 1 || padtext_array[index][i] != 2) {
        return 0;
    }
    ++i;
    while (padtext_array[index][i] != 0) {
        if (++i >= padded_msg_size) return 0;
    }
    int plaintext_start_index = i + 1;
    *msg_size = padded_msg_size - plaintext_start_index;
    plaintext_array[index] = new unsigned char[padded_msg_size + 1 - plaintext_start_index]();
    while (++i < padded_msg_size) {
        plaintext_array[index][i - plaintext_start_index] = padtext_array[index][i];
    }
    return 1;
}

void printPlaintextArray(int print_title) {
    if (plaintext_array) {
        if (print_title)
        cout << "plaintext_array:\n\n";
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            int count = i == 0 ? FIRST_BLOCK_SIZE : MAX_PLAIN_BLOCK_SIZE;
            for (size_t j = 0; j < count; j++)
            {
                cout << charToBinaryString(plaintext_array[i][j]) << " ";
            }
        }
        cout << endl;
    }
}

void printPlaintextArrayAsHex(int print_title) {
    if (plaintext_array) {
        if (print_title)
        cout << "plaintext_array:\n\n";
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            int count = i == 0 ? FIRST_BLOCK_SIZE : MAX_PLAIN_BLOCK_SIZE;
            for (size_t j = 0; j < count; j++)
            {
                unsigned char c = plaintext_array[i][j];
                char c1 = (c >> 4);
                c1 += c1 < 10 ? '0': 'A' - 10;
                char c2 = (c & 0xF);
                c2 += c2 < 10 ? '0': 'A' - 10;
                cout << c1 << c2 << " ";
            }
        }
        cout << endl;
    }
}

void printPlaintextArrayAsText(int print_title) {
    if (plaintext_array) {
        if (print_title)
        cout << "plaintext_array:\n\n";
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            int count = i == 0 ? FIRST_BLOCK_SIZE : MAX_PLAIN_BLOCK_SIZE;
            for (size_t j = 0; j < count; j++)
            {
                cout << (char)plaintext_array[i][j];
            }
        }
        cout << endl;
    }
}

void printPadtextArray(int print_title) {
    if (padtext_array) {
        if (print_title)
        cout << "padtext_array:\n\n";
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            for (size_t j = 0; j < CIPHER_BLOCK_SIZE; j++)
            {
                cout << "";
                cout << charToBinaryString(padtext_array[i][j]) << " ";
            }
            cout << endl;
        }
        cout << endl;
    }
}

void printPadtextArrayB(int print_title) {
    if (padtext_array_b && padtext_array_b[0] != 0) {
        if (print_title)
        cout << "padtext_array_b:\n\n";
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            cout << padtext_array_b[i] << endl;
        }
        cout << endl;
    }
}

void printCiphertextArrayB(int print_title) {
    if (ciphertext_array_b && ciphertext_array_b[0] != 0) {
        if (print_title)
        cout << "ciphertext_array_b:\n\n";
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            cout << ciphertext_array_b[i] << endl;
        }
        cout << endl;
    }
}

void printCiphertextArray(int print_title) {
    if (ciphertext_array) {
        if (print_title)
        cout << "ciphertext_array:\n\n";
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            for (size_t j = 0; j < CIPHER_BLOCK_SIZE; j++)
            {
                cout << charToBinaryString(ciphertext_array[i][j]) << " ";
            }
        }
        cout << endl;
    }
}

void printMessageArrays() {
    printPlaintextArray(1);
    printPadtextArray(1);
    printPadtextArrayB(1);
    printCiphertextArrayB(1);
    printCiphertextArray(1);
}

void clearMessageArrays() {
    if (plaintext_array) {
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            delete[] (unsigned char*) (plaintext_array[i]);
        }
        delete[] (unsigned char**) plaintext_array;
    }
    if (padtext_array) {
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            delete[] (unsigned char*) (padtext_array[i]);
        }
        delete[] (unsigned char**) padtext_array;
    }
    if (padtext_array_b) {
        delete[] padtext_array_b;
    }
    if (ciphertext_array_b) {
        delete[] ciphertext_array_b;
    }
    if (ciphertext_array) {
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            delete[] (unsigned char*) (ciphertext_array[i]);
        }
        delete[] (unsigned char**) ciphertext_array;
    }
}

void ERROR(string err_msg) {
    if (err_msg != "") ERROR_MSG += err_msg;
    cout << ERROR_MSG;
    exit(1);
}
