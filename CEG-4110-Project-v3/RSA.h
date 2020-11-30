#pragma once
#include "const.h"
using namespace std;

/*RSA Class
* This class could gerate the prime pair (p and q) and compute coresponding 
* product (n), public key (e) and private key (d).
* 
* Only product, public key and private key could be access outside the class.
* The two primes will be delete after gerating all the need values.
*/
class RSA {
public:
	RSA();

	N_NUM_TYPE getPrimeProduct();
	N_NUM_TYPE getPublicKey();
	N_NUM_TYPE getPrivateKey();
private:
	NUM_TYPE p;
	NUM_TYPE q;
	N_NUM_TYPE n;
	N_NUM_TYPE e;
	N_NUM_TYPE d;

	int generatePrime(NUM_TYPE& p , NUM_TYPE& q);
	N_NUM_TYPE computeE(NUM_TYPE const& p, NUM_TYPE const& q);
	N_NUM_TYPE computeD(NUM_TYPE const& p, NUM_TYPE const& q, NUM_TYPE const& e);
	N_NUM_TYPE gcdAlgorithm(N_NUM_TYPE const& a, N_NUM_TYPE const& b);

	void printValues();
};