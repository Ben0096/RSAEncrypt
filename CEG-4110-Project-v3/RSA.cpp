#pragma once
#include "RSA.h"

RSA::RSA() {
	generatePrime(p, q);
	n = p * q;
	e = computeE(p, q);
	d = computeD(p, q, e);

#ifdef DEMONSTRATION
	printValues();
#endif // DEMONSTRATION

	p = 0;
	q = 0;

#ifdef DEMONSTRATION
	cout << "p and q have been delete!" << endl;
#endif // DEMONSTRATION
}

N_NUM_TYPE RSA::getPrimeProduct() {
	return n;
}

N_NUM_TYPE RSA::getPublicKey() {
	return e;
}

N_NUM_TYPE RSA::getPrivateKey() {
	return d;
}

int RSA::generatePrime(NUM_TYPE& p, NUM_TYPE& q) {
	srand((unsigned int)time(NULL));
	size_t index = rand() % (2048 - 54) + 54; // 54th is the one > 256
	p = primes[index];
	index = rand() % (2048 - 54) + 54; // 54th is the one > 256
	q = primes[index];
	return 1;
}

N_NUM_TYPE RSA::computeE(NUM_TYPE const& p, NUM_TYPE const& q) {
	N_NUM_TYPE r = (p - 1) * (q - 1);
	N_NUM_TYPE e = 2;

	for (; e < r && gcdAlgorithm(e, r) != 1; e++);

	return e;
}

N_NUM_TYPE RSA::computeD(NUM_TYPE const& p, NUM_TYPE const& q, NUM_TYPE const& e) {
	N_NUM_TYPE r = (p - 1) * (q - 1);
	N_NUM_TYPE d = 2;

	for (; (e * d) % r != 1; d++);

	return d;
}

N_NUM_TYPE RSA::gcdAlgorithm(N_NUM_TYPE const& a, N_NUM_TYPE const& b) {//Euclidean algorithm
	N_NUM_TYPE bigTmp = a;
	N_NUM_TYPE smallTmp = b % a;

	while (smallTmp != 0) {
		N_NUM_TYPE oldBigTmp = bigTmp;
		bigTmp = smallTmp;
		smallTmp = oldBigTmp % smallTmp;
	}

	return bigTmp;
}

void RSA::printValues() {
	cout << "\nRSA:" << endl;
	cout << "p: " << p << endl;
	cout << "q: " << q << endl;
	cout << "n: " << n << endl;
	cout << "e: " << e << endl;
	cout << "d: " << d << endl;
}
