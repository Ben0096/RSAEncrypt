// CEG-4110-Project-v3.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "const.h"
#include "RSA.h"
#include "MethodRSA.h"

using namespace std;

//01001010 01101111 01101000 01101110 00100000 01100101 01110010 01101001 01101011 01110011 01101111 01101110
int main() {
	string msg;
	cout << "intput: ";
	getline(cin, msg);
	cout << endl;

	NUM_TYPE* numArray = NULL;
	size_t size;
	if (MethodRSA::strToNumArray(msg, &numArray, size) == 0) {
		cout << "INVALID INPUT" << endl;
		exit(0);
	}
	else {
		string msgInChar = "";
		MethodRSA::biStrToChar(msg, msgInChar);
		cout << "The input in chars is: " << msgInChar << endl;
	}

	cout << "\nmessage array:\n";
	for (size_t i = 0; i < size; i++) {
		cout << i << ": " << numArray[i] << endl;
	}

	RSA rsa = RSA();

	N_NUM_TYPE* encrytedArray = NULL;
	MethodRSA::pubEncrypt(rsa.getPublicKey(), rsa.getPrimeProduct(), numArray, size, &encrytedArray);

	cout << "\nencrypted array:\n";
	for (size_t i = 0; i < size; i++) {
		cout << i << ": " << encrytedArray[i] << endl;
	}

	NUM_TYPE* decryptedArray = NULL;
	MethodRSA::pubDecrypt(rsa.getPrivateKey(), rsa.getPrimeProduct(), encrytedArray, size, &decryptedArray);
	cout << "\ndecrypted array: (should be same as message array)\n";
	for (size_t i = 0; i < size; i++) {
		cout << i << ": " << decryptedArray[i] << endl;
	}

	cout << "\ndecrypted array to binary string: (should be same as input)\n";
	string binaryStr = "";
	MethodRSA::numArrayToStr(decryptedArray, size, binaryStr);
	cout << binaryStr << endl << endl;

	string binaryStrInChar;
	MethodRSA::biStrToChar(msg, binaryStrInChar);
	cout << "The decrypted array in chars is: " << binaryStrInChar << endl << endl;
	cout << "The DEMO is end" << endl << endl << endl;
}