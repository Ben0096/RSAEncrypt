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
string ERROR_INVALID_ARGS = "You must provide all arguments. For example:\nrsa -e -k key_components.txt -f filename.ext -o outfilename.ext\n\n";

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
 * 128 is the size when using 1024-bit encryption key
 */
int CIPHER_CHUNK_SIZE = 128;
/**
 * The minimum amount of padding to add to plaintext chunks before
 * encrypting them.  The amount of random bytes added is equal to
 * MIN_PAD - 3.
 * 
 * PKCS#1 reccommends a value of at least 11.
 */
int MIN_PAD = 4;
// todo: put MIN_PAD back to 11
/**
 * This is the maximum size, in bytes, that chunks of data (plaintext)
 * can split into in order to be used in RSA encryption.
 *  
 * 117 bytes per encryption chunk is the MAX_PLAIN_CHUNK_SIZE for a
 * key.n size of 128.  (1024 bit)
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
int MESSAGE_SIZE = 0;
/**
 * The first chunk of bytes that the plaintext is split into will likely
 * be less than MAX_PLAIN_CHUNK_SIZE bytes.  This is the size in bytes
 * of that first chunk.
 */
int FIRST_CHUNK_SIZE = 0;
/**
 * The size for the arrays that will hold the plaintext, padded plaintext, and ciphertext.
 * 
 * This is the number of chunks that the message will be split into
 * in order to perform the encryption and decryption.
 */
int MSG_ARRAY_SIZE = 0;
unsigned char** plaintext_array = nullptr;
unsigned char** padtext_array = nullptr;
BigInt* padtext_array_b = nullptr;
BigInt* ciphertext_array_b = nullptr;
unsigned char** ciphertext_array = nullptr;

int readRSAKeyComponentsFile(string filename, RSAKey& key);
string readNextHexValue(ifstream &in, string &line);
int pkcs1pad2(int padded_msg_size, int msg_size, int index);
int pkcs1unpad2(int padded_msg_size, int* msg_size, int index);
void printMessageArrays();
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
        CIPHER_CHUNK_SIZE = bytelength(key.n);
        if (CIPHER_CHUNK_SIZE < 16) {
            ERROR("ERROR: please provide an RSA key that's 128 bits or larger.\n");
            return 0;
        }
        MAX_PLAIN_CHUNK_SIZE = CIPHER_CHUNK_SIZE - MIN_PAD;
    } else return 0;
    
    if (strcmp(line.substr(0,15).c_str(), "publicExponent:") == 0) {
        key.e = extractPublicExponent(line);
    } else return 0;
    cout << "Public Exponent is: " << key.e << endl;
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
        int chunk_size = (i == 0) ? FIRST_CHUNK_SIZE : MAX_PLAIN_CHUNK_SIZE;
        // for (size_t j = 0; j < chunk_size; j++) {
        //     in.read((char*)&plaintext_array[i][j], sizeof(unsigned char));
        // }
        in.read((char*)plaintext_array[i], sizeof(unsigned char) * chunk_size);
    }
    in.close();
    return 1;
}

/**
 * Gets binary info from file and stores it in global plaintext_array.
 * 
 * Sets MESSAGE_SIZE
 * Sets MSG_ARRAY_SIZE
 * Sets FIRST_CHUNK_SIZE
 * 
 * Initializes plaintext_array and fills it with values from the file given by filename
 */ 
int getPlaintextFromFile(string filename) {
    // set global variables that are based on file size
    MESSAGE_SIZE = getFilesize(filename);
    if (!MESSAGE_SIZE || key.n == 0) return 0;
    MSG_ARRAY_SIZE = (MESSAGE_SIZE + MAX_PLAIN_CHUNK_SIZE - 1) / MAX_PLAIN_CHUNK_SIZE;
    FIRST_CHUNK_SIZE = MESSAGE_SIZE % MAX_PLAIN_CHUNK_SIZE;
    if (FIRST_CHUNK_SIZE == 0) FIRST_CHUNK_SIZE = MAX_PLAIN_CHUNK_SIZE;
    // initialize plaintext_array
    plaintext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        int chunk_size;
        if (i == 0) {
            chunk_size = FIRST_CHUNK_SIZE;
        } else {
            chunk_size = MAX_PLAIN_CHUNK_SIZE;
        }
        plaintext_array[i] = new unsigned char[chunk_size]();
    }
    // fill plaintext_array with contents from file
    readInputFile(filename);

    return 1;
}

// int shoveMessageIntoByteArray(string msg) {
//     for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
//         int count = i == 0 ? FIRST_CHUNK_SIZE : MAX_PLAIN_CHUNK_SIZE;
//         for (size_t j = 0; j < count; j++) {
//             plaintext_array[i][j] = (unsigned char) msg.at((i == 0) ? j : j + FIRST_CHUNK_SIZE + (i - 1) * MAX_PLAIN_CHUNK_SIZE);
//         }
//     }
//     return 1;
// }

// int getPlaintextFromMessage(string msg) {
//     MESSAGE_SIZE = msg.length();
//     if (!MESSAGE_SIZE || key.n == 0) return 0;
//     MSG_ARRAY_SIZE = (MESSAGE_SIZE + MAX_PLAIN_CHUNK_SIZE - 1) / MAX_PLAIN_CHUNK_SIZE;
//     FIRST_CHUNK_SIZE = MESSAGE_SIZE % MAX_PLAIN_CHUNK_SIZE;
//     plaintext_array = new unsigned char*[MSG_ARRAY_SIZE]();
//     for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
//         int chunk_size;
//         if (i == 0) {
//             chunk_size = FIRST_CHUNK_SIZE;
//         } else {
//             chunk_size = MAX_PLAIN_CHUNK_SIZE;
//         }
//         plaintext_array[i] = new unsigned char[chunk_size]();
//     }

//     shoveMessageIntoByteArray(msg);

//     return 1;
// }

int padPlaintext() {

    padtext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        int chunk_size = (i == 0) ? FIRST_CHUNK_SIZE : MAX_PLAIN_CHUNK_SIZE;
        pkcs1pad2(CIPHER_CHUNK_SIZE, chunk_size, i);
    }
    padtext_array_b = new BigInt[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        byteArrayToBigInt(padtext_array_b[i], padtext_array[i], CIPHER_CHUNK_SIZE);
    }
    return 1;
}

int modExpoPadtext() {
    
    ciphertext_array_b = new BigInt[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        ciphertext_array_b[i] = modExpo(padtext_array_b[i], key.e, key.n);
    }
    ciphertext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        ciphertext_array[i] = new unsigned char[CIPHER_CHUNK_SIZE]();
        bigIntToByteArray(ciphertext_array_b[i], ciphertext_array[i], CIPHER_CHUNK_SIZE);
    }
    return 1;
}

int writeCipherToFile(string outfile) {
    ofstream out;
    out.open(outfile, ios::out | ios::binary);
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        for (size_t j = 0; j < CIPHER_CHUNK_SIZE; j++)
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
        // for (size_t j = 0; j < CIPHER_CHUNK_SIZE; j++) {
        //     in.read((char*)&ciphertext_array[i][j], sizeof(unsigned char));
        // }
        in.read((char*)ciphertext_array[i], sizeof(unsigned char) * CIPHER_CHUNK_SIZE);
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
    MSG_ARRAY_SIZE = MESSAGE_SIZE / CIPHER_CHUNK_SIZE; // ciphertext must always be a multiple of 128 bytes in size for 1024 bit keys
    ciphertext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        ciphertext_array[i] = new unsigned char[CIPHER_CHUNK_SIZE]();
    }

    readCipherFile(filename);

    return 1;
}

int modExpoCiphertext() {
    
    ciphertext_array_b = new BigInt[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        byteArrayToBigInt(ciphertext_array_b[i], ciphertext_array[i], CIPHER_CHUNK_SIZE);
    }

    padtext_array_b = new BigInt[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        padtext_array_b[i] = modExpo(ciphertext_array_b[i], key.d, key.n);
    }

    return 1;
}

int unpadPadtext() {
    // convert padtext_array_b to padtext_array
    padtext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        padtext_array[i] = new unsigned char[CIPHER_CHUNK_SIZE]();
        bigIntToByteArray(padtext_array_b[i], padtext_array[i], CIPHER_CHUNK_SIZE);
    }
    // unpad padtext_array and put results into plaintext_array
    plaintext_array = new unsigned char*[MSG_ARRAY_SIZE]();
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++) {
        int chunk_size = 0;
        pkcs1unpad2(CIPHER_CHUNK_SIZE, &chunk_size, i);
        if (i == 0) FIRST_CHUNK_SIZE = chunk_size;
    }
    return 1;
}

int writePlaintextToFile(string outfile) {
    ofstream out;
    out.open(outfile, ios::out | ios::binary);
    for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
    {
        int count = i == 0 ? FIRST_CHUNK_SIZE : MAX_PLAIN_CHUNK_SIZE;
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
    // srand(time(0));  //todo uncomment this line
    while (n > 2) {
        unsigned char c;
        while ((c = rand()) == 0){}
        padtext_array[index][--n] = c;
    }
    padtext_array[index][--n] = 2;
    padtext_array[index][--n] = 0;
    return 1;
}

// pad_array -> plain_array
// set msg_size to
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
    // delete[] padtext;
    // *padtext_array[index] = *plaintext_array[index];
    return 1;
}

void printMessageArrays() {
    cout << "MSG_ARRAY_SIZE " << MSG_ARRAY_SIZE << endl;
    if (plaintext_array) {
        cout << "plaintext_array:" << endl; 
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            int count = i == 0 ? FIRST_CHUNK_SIZE : MAX_PLAIN_CHUNK_SIZE;
            for (size_t j = 0; j < count; j++)
            {
                cout << charToBinaryString(plaintext_array[i][j]) << " ";
            }
            cout << endl;
        }
    }
    if (padtext_array) {
        cout << "padtext_array:" << endl; 
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            for (size_t j = 0; j < CIPHER_CHUNK_SIZE; j++)
            {
                cout << "";
                cout << charToBinaryString(padtext_array[i][j]) << " ";
            }
            cout << endl;
        }
    }
    if (padtext_array_b && padtext_array_b[0] != 0) {
        cout << "padtext_array_b:" << endl; 
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            cout << padtext_array_b[i] << endl;;
        }
    }
    if (ciphertext_array_b && ciphertext_array_b[0] != 0) {
        cout << "ciphertext_array_b:" << endl; 
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            cout << ciphertext_array_b[i] << endl;;
        }
    }
    if (ciphertext_array) {
        cout << "ciphertext_array:" << endl; 
        for (size_t i = 0; i < MSG_ARRAY_SIZE; i++)
        {
            for (size_t j = 0; j < CIPHER_CHUNK_SIZE; j++)
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

void ERROR(string err_msg) {
    if (err_msg != "") ERROR_MSG += err_msg;
    cout << ERROR_MSG;
    exit(1);
}

void test2() {
    cout << "test2()\n\n" << endl;
    
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

    milliseconds time1 = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    if (argc < 8) {
        test2();
        ERROR(ERROR_INVALID_ARGS);
        return 0;
    }
    if (strcmp(argv[1], "-e") == 0) {
        encrypt = true;
    } else if (strcmp(argv[1], "-d") == 0) {
        decrypt = true;
    } else {
        ERROR(ERROR_INVALID_ARGS);
        return 0;
    }
    if (strcmp(argv[2], "-k") == 0 &&
        strcmp(argv[4], "-f") == 0 &&
        strcmp(argv[6], "-o") == 0) {
            readRSAKeyComponentsFile(argv[3], key);
            if (encrypt) encryptFile(argv[5], argv[7]);
            else if (decrypt) decryptFile(argv[5], argv[7]);
    } else {
        ERROR(ERROR_INVALID_ARGS);
        return 0;
    }

    printMessageArrays();
    
    milliseconds time2 = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    cout << "time2 - time1: " << (time2 - time1).count() << endl;

    return 1;
}