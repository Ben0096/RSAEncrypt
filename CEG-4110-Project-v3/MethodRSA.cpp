#include "MethodRSA.h"

//msg should be 8bits binary number seperated with space
int MethodRSA::strToNumArray(string msg, NUM_TYPE** numArrayPtr, size_t& size) {
	if ((msg.size() + 1) % 9 == 0) {
#ifdef DEBUG_strToNumArray
		cout << "flow 1" << endl;
#endif // DEBUG_strToNumArray
		size_t numbers = (msg.size() + 1) / 9;
		size_t remain = numbers % NUM_BYTES;
		if (remain == 0) {
#ifdef DEBUG_strToNumArray
			cout << "flow 1-1" << endl;
#endif // DEBUG_strToNumArray
			size = numbers / NUM_BYTES;
			delete[](*numArrayPtr);
			*numArrayPtr = new NUM_TYPE[size];
			for (size_t i = 0; i < size; i++) {
				size_t startIndex = i * NUM_BYTES * 9;
				(*numArrayPtr)[i] = (NUM_TYPE)stoul(msg.substr(startIndex, 8), NULL, 2);
				for (size_t j = 1; j < NUM_BYTES; j++) {
#ifdef DEBUG_strToNumArray
					cout << "before " << (*numArrayPtr)[i] << endl;
#endif // DEBUG_strToNumArray
					(*numArrayPtr)[i] *= 256;
					startIndex = (i * NUM_BYTES + j) * 9;
					(*numArrayPtr)[i] += (NUM_TYPE)stoul(msg.substr(startIndex, 8), NULL, 2);
#ifdef DEBUG_strToNumArray
					cout << "after " << (*numArrayPtr)[i] << endl;
#endif // DEBUG_strToNumArray
				}
			}
		}
		else {// numbers % NUM_BYTES != 0
#ifdef DEBUG_strToNumArray
			cout << "flow 1-2" << endl;
#endif // DEBUG_strToNumArray
			size = numbers / NUM_BYTES + 1;
			delete[](*numArrayPtr);
			*numArrayPtr = new NUM_TYPE[size];
			for (size_t i = 0; i < size - 1; i++) {
				size_t startIndex = i * NUM_BYTES * 9;
				(*numArrayPtr)[i] = (NUM_TYPE)stoul(msg.substr(startIndex, 8), NULL, 2);
				for (size_t j = 1; j < NUM_BYTES; j++) {
					(*numArrayPtr)[i] *= 256;
					startIndex = (i * NUM_BYTES + j) * 9;
					(*numArrayPtr)[i] += (NUM_TYPE)stoul(msg.substr(startIndex, 8), NULL, 2);
				}
			}
			size_t lastIndex = size - 1;
			(*numArrayPtr)[lastIndex] = (NUM_TYPE)stoul(msg.substr(lastIndex * NUM_BYTES * 9, 8), NULL, 2);
			for (size_t j = 1; j < remain; j++) {
				(*numArrayPtr)[lastIndex] *= 256;
				(*numArrayPtr)[lastIndex] += (NUM_TYPE)stoul(msg.substr((lastIndex * NUM_BYTES + j) * 9, 8), NULL, 2);
			}
		}
		return 1;
	}
	else {
#ifdef DEBUG_strToNumArray
		cout << "flow 2" << endl;
#endif // DEBUG_strToNumArray
		return 0;
	}
}
int MethodRSA::numArrayToStr(NUM_TYPE* const& numArray, size_t const& size, string& msg) {
	msg = "";
	for (size_t i = 0; i < size - 1; i++) {
		for (size_t j = 0; j < NUM_BYTES; j++) {
			string binaryStr = (bitset<8 * NUM_BYTES>(numArray[i])).to_string().substr(8 * j, 8);
			msg.append(binaryStr + " ");
		}
	}

	bool foundOne = false;
	for (size_t i = 0; i < NUM_BYTES - 1; i++) {
		string binaryStr = (bitset<8 * NUM_BYTES>(numArray[size - 1])).to_string().substr(8 * i, 8);
		foundOne = stoul(binaryStr, NULL, 2) > 0 ? true : foundOne;
		if (foundOne) msg.append(binaryStr + " ");
	}
	msg.append((bitset<8 * NUM_BYTES>(numArray[size - 1])).to_string().substr(8 * (NUM_BYTES - 1), 8));

	return 1;
}

//msg should be 8bits binary number seperated with space
int MethodRSA::biStrToChar(string msg, string& outputStr) {
	if ((msg.size() + 1) % 9 == 0) {
		size_t numbers = (msg.size() + 1) / 9;
		outputStr = "";
		for (size_t i = 0; i < numbers; i++) {
			size_t startIndex = i * 9;
			bitset<8> b(msg.substr(startIndex, 8));
			outputStr += static_cast<unsigned char>(b.to_ulong());
		}
		return 1;
	}
	else {
		return 0;
	}
}

int MethodRSA::pubEncrypt(N_NUM_TYPE const& e, N_NUM_TYPE const& n,
	NUM_TYPE* const& input, size_t const& size, N_NUM_TYPE** output) {

	delete[](*output);
	(*output) = new N_NUM_TYPE[size];
	for (size_t i = 0; i < size; i++) {
		(*output)[i] = getPowerMod((N_NUM_TYPE)input[i], e, n);
	}
	return 1;
}

int MethodRSA::pubDecrypt(N_NUM_TYPE const& d, N_NUM_TYPE const& n,
	N_NUM_TYPE* const& input, size_t const& size, NUM_TYPE** output) {

	delete[](*output);
	(*output) = new NUM_TYPE[size];
	for (size_t i = 0; i < size; i++) {
		(*output)[i] = getPowerMod((N_NUM_TYPE)input[i], d, n);
	}
	return 1;
}

int MethodRSA::prvEncrypt(N_NUM_TYPE const& d, N_NUM_TYPE const& n,
	NUM_TYPE* const& input, size_t const& size, N_NUM_TYPE** output) {

	delete[](*output);
	(*output) = new N_NUM_TYPE[size];
	for (size_t i = 0; i < size; i++) {
		(*output)[i] = getPowerMod((N_NUM_TYPE)input[i], d, n);
	}
	return 1;
}

int MethodRSA::prvDecrypt(N_NUM_TYPE const& e, N_NUM_TYPE const& n,
	N_NUM_TYPE* const& input, size_t const& size, NUM_TYPE** output) {

	delete[](*output);
	(*output) = new NUM_TYPE[size];
	for (size_t i = 0; i < size; i++) {
		(*output)[i] = getPowerMod((N_NUM_TYPE)input[i], e, n);
	}
	return 1;
}


N_NUM_TYPE MethodRSA::getPowerMod(N_NUM_TYPE const& msg, N_NUM_TYPE const& power, N_NUM_TYPE const& n) {
	CAL_NUM_TYPE num = 1;
	for (N_NUM_TYPE i = 0; i < power; i++) {
		num *= msg;
		num %= n;
	}
	return (N_NUM_TYPE)num;
}
