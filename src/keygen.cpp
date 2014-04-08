#include <cassert>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <fstream>
#include <map>
using std::map;
using std::ifstream;
using std::ofstream;

#include "common.h"
#include "syspub.h"




const char* usage =
"Usage: keygen -[username] -[attr1 attr2  ...] \n"
"\n"
"Generation of user's secret keys\n"
"-h, help print message\n\n";

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



const char *pub_file = "./pub_key";
const char *msk_file = "./master_key";

struct sys_secret* seckey = NULL;
struct sys_public* pubkey = NULL;

void parse_args( int argc, char** argv );

void pubkey_from_file();
void seckey_from_file();


void parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
	{
		if(  !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf("MDS-CP-ABE VERSION 1.0\n ");
			exit(0);
		}
	}

	std::cout<<"Begin "<<std::endl;
	std::cout<<"KEY GENERATION ..."<<std::endl;
}


/*construct element from a string*/
void element_from_string( element_t h, char* s )
{
	unsigned char r[SHA_DIGEST_LENGTH+1];
	SHA1((unsigned char*) s, strlen(s), r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);
}



void pubkey_from_file()
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
	element_from_bytes(pubkey->G2beta, p); p+= l4;
	element_from_bytes(pubkey->Yt, p); p+= l5;

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

void seckey_from_file()
{
	if( seckey)
		return ;
	pairing_t p;
	seckey = new sys_secret;
	seckey->pairing_desc = const_cast<char*>(TYPE_A_PARAMS);
	pairing_init_set_buf(p, seckey->pairing_desc, strlen(seckey->pairing_desc));

	element_init_Zr(seckey->tau, pubkey->p);
	element_init_Zr(seckey->beta, pubkey->p);
	
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

static char* GetRequest_from_file(string filename)
{
	/*open user attribute file */
	ifstream f(filename.c_str());
	if(!f.good()){
		dprint("Invalid filename!\n");
		exit(-1);
	}

	/*read attribute file and generate secret key*/
	size_t l1,l2, vec_size, len_bytes;
	l1 = element_length_in_bytes(pubkey->g1);
	l2 = element_length_in_bytes(pubkey->g2);
	size_t index, maxindex = seckey->masterkey.size();
	element_t D1,D2, Di, uj, uV ,var1, var2;
	
	
	element_init_G1(D1, pubkey->p);
	element_init_G2(D2, pubkey->p);

	element_init_Zr(var1, pubkey->p);
	element_init_Zr(var2, pubkey->p);
	element_init_Zr(uV, pubkey->p);
	element_init_Zr(uj, pubkey->p);
	element_from_string( uj , const_cast<char*>(filename.c_str()) );
	
	
	element_add(var1, uj, seckey->tau);
	element_invert(var2, seckey->beta);
	element_mul(var1, var1, var2);
	element_pow_zn(D1, pubkey->g1, var1);
	element_pow_zn(D2, pubkey->g2, uj);
	
	f>>vec_size;
	assert( vec_size<10000 );
	len_bytes = l1 + l2 + vec_size*l1 + 3; // contains '\n'
	unsigned char* buf = new unsigned char[len_bytes];
	buf[len_bytes-1] = '\0';
	unsigned char *p = buf;
	element_to_bytes(p, D1); p+= l1;
	element_to_bytes(p, D2); p+= l2;
	*p++ = '\0';

	memcpy(p, &vec_size, sizeof(size_t));
	p += sizeof(size_t);
	*p++ = '\0';
	
	while(f>>index)
	{
		//assert(index<maxindex);
		if(index>maxindex)
			continue ;
		index--;
		element_init_G1(Di, pubkey->p);
		element_mul(uV, uj, seckey->masterkey[index].ver);
		element_pow_zn(D1, pubkey->g1, uV);
		element_mul(Di, D1, pubkey->pubkey[index].T);
		element_to_bytes( p, Di);
		p += l1;
	}
	return (char*)buf;
}

/*handle request from file*/
void handle_request()
{
	std::cout<<"A attribute set filename"<<std::endl;
	string filename("alice");
//	std::cin>>filename;

#ifdef NEED_TIME
	struct timeval start, end;
	gettimeofday(&start, NULL);
#endif
	char* buf = GetRequest_from_file(filename);
#ifdef NEED_TIME
	gettimeofday(&end, NULL);
	std::cout<<"Need time "<<end.tv_sec-start.tv_sec<<"s"<<(end.tv_usec-start.tv_usec)/1000<<"ms"<<std::endl;
#endif

	size_t len = strlen(buf);
	if(!buf){
		dprint("Get request from file err \n");
		return ;
	}

	/*create user secret key file*/
	string key_filename(filename);
	key_filename +=".sk";
	ofstream of(key_filename.c_str());
	if(!of.good()){
		dprint("Err create secret key file\n");
		return ;
	}
	
	of.write(buf, len);
	return ;
}

#define NEED_TIME

int main(int argc, char** argv)
{
	parse_args(argc, argv);
	
	pubkey_from_file();
	seckey_from_file();

	handle_request();
	return 0;
}






