#ifndef SYSPUB
#define SYSPUB

#include <glib.h>
#include <pbc.h>
#include <gmp.h>
#include <openssl/sha.h>

#include <vector>
using std::vector;


/* attribute public infomation*/
typedef struct attr_pub{
	element_t T; //  public key in G1
	element_t Version;  //public version key in G1
}attr_pub;

/*attribute secret information*/
typedef struct attr_master{
	//element_t t; //master key in G1
	element_t ver; //secret version in Zr
}attr_master;


/*system public parameters*/
/*
sys_public in memory looks like:
p, g1, g2, gt, Yt, G2beta, size_of_vector, attr_pub, ... attr_pub.
*/
typedef struct sys_public{
	char *pairing_desc;
	pairing_t p;        //bilinear  pairing
	element_t g1,g2,gt, Yt, G2beta;
	vector<struct attr_pub> pubkey;  //public key of attributes
}sys_public;


/*system secret*/ 
/*
sys_secret in memory looks like:
tau, beta, size_of_vector, attr_master, ... attr_master.
*/
typedef struct sys_secret{
	element_t tau;  // tau in Zr
	element_t beta;  //beta in Zr
	vector<struct attr_master > masterkey;  //
}sys_secret;

#endif
/* */
