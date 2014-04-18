#include "common.h"
extern "C"{ 
#include "jerasure.h"
#include "galois.h"
#include "cauchy.h"
}
#include <cstring>
#include <cassert>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <string>
#include <fstream>
using std::ifstream;
using std::ofstream;
using std::string;

#include <vector>
using std::vector;

const char* TYPE_A_PARAMS = "type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n";





const char* pub_file = "./pub_key";
const char* msk_file = "./master_key";
const char* config_file = "./attribute.conf";

extern struct sys_secret* seckey ;
extern struct sys_public* pubkey ;


/*construct element from a string*/
void element_from_string( element_t h, char* s )
{
	unsigned char r[SHA_DIGEST_LENGTH+1];
	SHA1((unsigned char*) s, strlen(s), r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);
}


/*read public key from a public file*/
void pubkey_from_file(struct sys_public *&pubkey)
{
	unsigned char buf[1024], *p;
	if(pubkey)
		return ;
	pubkey = new sys_public;
	ifstream f(pub_file);	
	if(!f.good()){
		delete pubkey;
		pubkey = NULL;
		dprint("File not exist!\n");
		exit(-1);
	}

	pubkey->pairing_desc = const_cast<char*>(TYPE_A_PARAMS);
	pairing_init_set_buf(pubkey->p , pubkey->pairing_desc ,strlen(pubkey->pairing_desc));
	
	element_init_G1(pubkey->g1, pubkey->p);
	element_init_G2(pubkey->g2, pubkey->p);
	element_init_GT(pubkey->gt, pubkey->p);
	element_init_G2(pubkey->G2beta, pubkey->p);
	element_init_GT(pubkey->Yt, pubkey->p);

	size_t  l1,l2,l3,l4,l5,l6,l7;
	size_t vec_size = 0;

	l1 = element_length_in_bytes(pubkey->g1);
	l2 = element_length_in_bytes(pubkey->g2);
	l3 = element_length_in_bytes(pubkey->gt);
	l4 = element_length_in_bytes(pubkey->Yt);
	l5 = element_length_in_bytes(pubkey->G2beta);

	l6 = l1;
	l7 = l1;
	
	f.read((char*)buf, l1+l2+l3+l4+l5+1 );
	p = buf;
	element_from_bytes(pubkey->g1, p); p+= l1;
	element_from_bytes(pubkey->g2, p); p+= l2;
	element_from_bytes(pubkey->gt, p); p+= l3;
	element_from_bytes(pubkey->Yt, p); p+= l4;
	element_from_bytes(pubkey->G2beta, p); p+= l5;

	f.read((char*)buf, sizeof(size_t)+1);
	memcpy(&vec_size, buf, sizeof(size_t));
	assert( vec_size <10000 );

	for(size_t i=0; i<vec_size; i++)
	{
		struct attr_pub tmp;
		f.read((char*)buf, l6);
		element_init_G1(tmp.T , pubkey->p);
		element_from_bytes(tmp.T , buf);
		f.read((char*)buf, l7);
		element_init_G1(tmp.Version , pubkey->p);
		element_from_bytes(tmp.Version, buf);

		pubkey->pubkey.push_back(tmp);
	}
	return ;
}	


/**/
void seckey_from_file(struct sys_secret *&seckey  , pairing_t p)
{
	if( seckey )
		return ;

	seckey = new sys_secret;
	element_init_Zr(seckey->tau, p);
	element_init_Zr(seckey->beta, p);
	
	ifstream f(msk_file);
	if(!f.good())
	{
		dprint("File not exist!\n");
		exit(-1) ;
	}
	unsigned char buf[1024];
	unsigned char *pb = buf;
	size_t l1,l2;
	l1 = element_length_in_bytes(seckey->tau);
	l2 = element_length_in_bytes(seckey->beta);

	f.read((char*)buf, l1+l2+1);
	element_from_bytes(seckey->tau, pb ); pb += l1;
	element_from_bytes(seckey->beta, pb );

	size_t vec_size;
	f.read((char*)buf, sizeof(size_t)+1);
	memcpy(&vec_size, (char*)buf, sizeof(size_t));
	assert( vec_size<10000);
	
	struct attr_master tmp;
	for(size_t i=0; i<vec_size; i++){
		element_init_Zr(tmp.ver, p);
		f.read((char*)buf, l1);
		element_from_bytes(tmp.ver, buf);
		seckey->masterkey.push_back(tmp);
	}
	return ;
}




/*free element in pubkey and seckey*/
void keys_free(struct sys_public *pubkey, struct sys_secret *seckey)
{
	if(seckey){	
		element_clear(seckey->tau);
		element_clear(seckey->beta);
		for(size_t i=0; i<seckey->masterkey.size(); i++)
			element_clear(seckey->masterkey[i].ver);
		delete seckey;
	}

	if(pubkey){
		element_clear( pubkey->g1);
		element_clear( pubkey->g2);
		element_clear(pubkey->gt);
		element_clear(pubkey->Yt );
		element_clear(pubkey->G2beta );
		for(size_t i=0;i<pubkey->pubkey.size(); i++)
		{
			element_clear(pubkey->pubkey[i].T);
			element_clear(pubkey->pubkey[i].Version);
		}
		/*pairing is needed to clear in the last*/
		pairing_clear(pubkey->p);
		delete pubkey;
	}
}


const size_t k = 20;
const size_t m = 20;
const size_t w = 8;
int *Cauchy_matrix =NULL;
vector< vector<element_s> > matrix;
/*Init a MDS code matrix*/
void Get_MDS_Matrix( struct sys_public *pubkey)
{
	if(!Cauchy_matrix)
		return ;
	Cauchy_matrix = cauchy_good_general_coding_matrix(k,m,w);
	if(NULL==Cauchy_matrix)
		return ;
	
	matrix.resize(m);
	size_t index = 0;
	for(size_t i=0;i<m;i++)
	{
		for(size_t j=0; j<k; j++)
		{
			element_s tmp;
			element_init_Zr(&tmp, pubkey->p);
			element_set_si(&tmp, Cauchy_matrix[index++]);
			matrix[i].push_back(tmp);
		}
	}
	return ;
}

void vec_mul(element_t res,  vector<element_s> &source,  size_t column,  struct sys_public *pubkey)
{
	element_t tmp;
	element_init_Zr(tmp, pubkey->p);
	element_set0(tmp);
	for(size_t i=0; i<source.size();i++)
	{
		element_mul(tmp, &source[i], &matrix[column][i]);
		element_set(res, tmp);
	}
	element_clear(tmp);
}
