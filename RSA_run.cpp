#include <iostream>
#include <string>
#include <ctime>
#include <chrono>
#include "RSA_enc.cpp"

using namespace std;
using namespace std::chrono;

string ERROR_INVALID_ARGS = "You must provide all arguments in the specified order. For example:\nrsa -e -k key_components.txt -f filename.ext -o outfilename.ext\n\nYou can also run a test by calling:\nrsa -t -k key_components.txt -f filename.ext\n";

int runTestCase(string keyfile, string testfile) {
    int filenamestartindex = -1;
    if (testfile.find('/') != std::string::npos)
        filenamestartindex = findLastIndex(testfile, '/');
    else if (testfile.find('\\') != std::string::npos)
        filenamestartindex = findLastIndex(testfile, '\\');
    int extnindex = findLastIndex(testfile, '.');

    if (testfile.length() == 0 || extnindex == -1) ERROR("Please provide a valid file name.");

    string testfilepath = testfile.substr(0, filenamestartindex + 1);
    string testfilename = testfile.substr(filenamestartindex + 1, extnindex - filenamestartindex - 1);
    string testfileextn = testfile.substr(extnindex);

    if (!readRSAKeyComponentsFile(keyfile)) return 0;

    cout << "\n\n=============== BEGINNING RSA ENCRYPTION ===============\n\n";

    milliseconds time1 = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    encryptFile(testfile, testfilepath + testfilename + "_encr.bin");

    milliseconds time2 = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    if (strcmp(testfileextn.c_str(), ".txt") == 0) {
        cout << "\nInput file as text:\n";
        printPlaintextArrayAsText();
    }
    cout << "\nInput file as binary data:\n";
    printPlaintextArray();
    cout << "\nOutput file (encrypted) as binary data:\n";
    printCiphertextArray();

    clearMessageArrays();

    cout << "\n\n=============== BEGINNING RSA DECRYPTION ===============\n\n";

    milliseconds time3 = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    decryptFile(testfilepath + testfilename + "_encr.bin", testfilepath + testfilename + "_decr" + testfileextn);

    milliseconds time4 = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    cout << "\nDecrypted file as binary data: (should be the same as input file above)\n";
    printPlaintextArray();
    if (strcmp(testfileextn.c_str(), ".txt") == 0) {
        cout << "\nDecrypted file as text: (should be the same as input file above)\n";
        printPlaintextArrayAsText();
    }
    cout << endl;

    cout << "\n\n=============== RESULTS ===============\n\n";

    cout << "Time to encrypt: " << (time2 - time1).count() << " milliseconds\n";
    cout << "Time to decrypt: " << (time4 - time3).count() << " milliseconds\n\n";

    cout << "The result files, " + testfilename + "_encr.bin and " + testfilename
        + "_decr" + testfileextn + " can be found in the same directory as the original file.\n";

    return 1;
}

/**
 * rsa -- encrypt or decrypt a file using rsa
 * 
 * rsa [-e | -d] [-k] private_key_components_file [-f] infile [-o] outfile 
 * 
 * -e   Encrypt the input
 * 
 * -d   Decrypt the input
 * 
 * rsa [-t] [-k] private_key_components_file [-f] infile
 * 
 * -t   Run a test case
 * 
 **/ 
int main(int argc, char** argv) {

    milliseconds time1 = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    if (argc >= 6 &&
        strcmp(argv[1], "-t") == 0 && 
        strcmp(argv[2], "-k") == 0 && 
        strcmp(argv[4], "-f") == 0) {
            decrypt = true;
            return runTestCase(argv[3], argv[5]);
    }
    if (argc < 8) {
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
            readRSAKeyComponentsFile(argv[3]);
            if (encrypt) encryptFile(argv[5], argv[7]);
            else if (decrypt) decryptFile(argv[5], argv[7]);
    } else {
        ERROR(ERROR_INVALID_ARGS);
        return 0;
    }
    
    milliseconds time2 = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    cout << "total time taken: " << (time2 - time1).count() << " milliseconds" << endl;

    return 1;
}