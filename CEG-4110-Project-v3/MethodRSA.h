#pragma once
#include "const.h"
using namespace std;

class MethodRSA {
public:
	//These three function is for data formating
	static int strToNumArray(string msg, NUM_TYPE** numArray, size_t& size);
	static int numArrayToStr(NUM_TYPE* const& numArray, size_t const& size, string& msg);
	static int biStrToChar(string msg, string& outputStr);

	//Encryption and Decryption functions
	static int pubEncrypt(N_NUM_TYPE const& e, N_NUM_TYPE const& n, NUM_TYPE* const& input, size_t const& size, N_NUM_TYPE** output);
	static int pubDecrypt(N_NUM_TYPE const& d, N_NUM_TYPE const& n, N_NUM_TYPE* const& input, size_t const& size, NUM_TYPE** output);
	static int prvEncrypt(N_NUM_TYPE const& d, N_NUM_TYPE const& n, NUM_TYPE* const& input, size_t const& size, N_NUM_TYPE** output);
	static int prvDecrypt(N_NUM_TYPE const& e, N_NUM_TYPE const& n, N_NUM_TYPE* const& input, size_t const& size, NUM_TYPE** output);
	static N_NUM_TYPE getPowerMod(N_NUM_TYPE const& msg, N_NUM_TYPE const& power, N_NUM_TYPE const& n);
};

