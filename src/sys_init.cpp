#include <cstdio>
#include <cassert>
#include <cstring>
#include <fstream>
#include <iostream>
using std::cout;
using std::endl;
using std::ifstream;
using std::ofstream;
//#include <sys/mem.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>

#include "common.h"
#include "syspub.h"

const char* usage =
"Usage: cpabe-setup [OPTION ...]\n"
"\n"
"Generate system parameters, a public key, and a master secret key\n"
"for use with cpabe-keygen, cpabe-enc, and cpabe-dec.\n"
"\n"
"Output will be written to the files \"pub_key\" and \"master_key\"\n"
"unless the --output-public-key or --output-master-key options are\n"
"used.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -p, --output-public-key FILE  write public key to FILE\n\n"
" -m, --output-master-key FILE  write master secret key to FILE\n\n"
"                               (only for debugging)\n\n";


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

struct sys_public* pubkey =NULL; 
struct sys_secret* seckey =NULL;

void element_from_string( element_t h, char* s );
void setup();
void parse_args( int argc, char** argv );
void attr_from_file();

void sync_pubkey_file();
void sync_seckey_file();


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
		else if( !strcmp(argv[i], "-p") || !strcmp(argv[i], "--output-public-key") )
		{
			if( ++i >= argc )
			{
				printf("%s\n",usage);
				exit(0);
			}
			else
				pub_file = argv[i];
		}
		else if( !strcmp(argv[i], "-m") || !strcmp(argv[i], "--output-master-key") )
		{
			if( ++i >= argc )
			{
				printf("%s",usage);
				exit(0);
			}	
			else
				msk_file = argv[i];
		}	
	}

	cout<<"Begin Setup"<<endl;
	cout<<"Setup ..."<<endl;
}


/*construct element from a string*/
void element_from_string( element_t h, char* s )
{
	unsigned char r[SHA_DIGEST_LENGTH+1];
	SHA1((unsigned char*) s, strlen(s), r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);
}


/*Read the attribute config file , init the public and secret information of all attributes*/
void attr_from_file()
{
	assert(pubkey && seckey);

	ifstream f(config_file, std::ifstream::binary);

	string buf;
	if(!f.good())
	{
		dprint("NULL file point\n");
		exit(-1);
	}
	while(f>>buf)
	{
		struct attr_pub temppub;    //  temp var of attr public key
		struct attr_master tempmas;  //
		element_init_G1(temppub.T, pubkey->p);
		element_init_G1(temppub.Version, pubkey->p);
		element_init_Zr( tempmas.ver , pubkey->p);
		

		element_from_string( temppub.T , (char*)buf.c_str() );  // generate public key of attr
		element_random( tempmas.ver);                // secret version
		element_pow_zn( temppub.Version, pubkey->g1 , tempmas.ver );   //public version
		
		pubkey->pubkey.push_back( temppub );
		seckey->masterkey.push_back(tempmas );
	}
	return ;
}

void setup()
{
/* init secret information of system*/
	if(!seckey)
		seckey = new sys_secret;
	if(!pubkey)
		pubkey = new sys_public;
	pubkey->pairing_desc = const_cast<char*>(TYPE_A_PARAMS);
	pairing_init_set_buf(pubkey->p, pubkey->pairing_desc, strlen(pubkey->pairing_desc));
	
	seckey->pairing_desc = const_cast<char*>(TYPE_A_PARAMS);
	element_init_Zr(seckey->tau, pubkey->p);
	element_init_Zr(seckey->beta, pubkey->p);
	element_random(seckey->tau);
	element_random(seckey->beta);
	
/*init for public secret infomation*/


	element_init_G1(pubkey->g1, pubkey->p);
	element_init_G2(pubkey->g2, pubkey->p);
	element_init_GT(pubkey->gt, pubkey->p);
	element_init_G2(pubkey->G2beta, pubkey->p);
	element_init_GT(pubkey->Yt, pubkey->p);

	element_random(pubkey->g1);
	element_random(pubkey->g2);
	element_pow_zn(pubkey->G2beta, pubkey->g2, seckey->beta );

	pairing_apply(pubkey->Yt, pubkey->g1, pubkey->g2, pubkey->p);
//init for each attribute	
	attr_from_file();
}


static unsigned char * pubkey_to_membuf(size_t *file_len)
{
	unsigned char *p=NULL, *buf =NULL;
	size_t len_size = 0, l1,l2,l3,l4,l5,l6,l7;
	size_t vec_size = 0;
	l1 = element_length_in_bytes(pubkey->g1);
	l2 = element_length_in_bytes(pubkey->g2);
	l3 = element_length_in_bytes(pubkey->gt);
	l4 = element_length_in_bytes(pubkey->Yt);
	l5 = element_length_in_bytes(pubkey->G2beta);

	l6 = 0;
	l7 = 0;
	vec_size = pubkey->pubkey.size();
	if( vec_size>0 )
	{
		l6 = element_length_in_bytes(pubkey->pubkey[0].T);
		l7 = element_length_in_bytes(pubkey->pubkey[0].Version) ;
	}

	len_size = l1 + l2 + l3 + l4 + l5 + vec_size*(l6 + l7);
	len_size += 3+sizeof(size_t);
	buf = new unsigned char[len_size];
	buf[len_size-1] = '\0';
	p = buf;
	//if(!p)
	//	return NULL ;
	
	
	element_to_bytes(p, pubkey->g1); p += l1; 
	element_to_bytes(p, pubkey->g2); p += l2;	
	element_to_bytes(p, pubkey->gt); p += l3;
	element_to_bytes(p, pubkey->Yt); p += l4;
	element_to_bytes(p, pubkey->G2beta); p += l5;
	*p++ = '\0';


	memcpy(p, &vec_size, sizeof(vec_size));
	p += sizeof(vec_size);
	*p++ = '\0';

	for(size_t i=0;i<vec_size;i++)
	{
		element_to_bytes(p, pubkey->pubkey[i].T );
		p += l6;
		element_to_bytes(p, pubkey->pubkey[i].Version);
		p += l7;
	}
	*file_len = len_size;
	return buf;
}


void sync_pubkey_file()
{
	ofstream f(pub_file, std::ofstream::out|std::ofstream::trunc| std::ofstream::binary);
	unsigned char *buf = NULL;
	size_t buf_len=0;

	if(!f.good())
	{
		dprint("Error open pubfile\n");
		return ;
	}

	buf = pubkey_to_membuf(&buf_len);
	if(!buf)
	{
		//dprint("Error key to string\n");
		return ;
	}
	f.write( (char*)buf, buf_len);

	delete []buf;
	return ;
}

static unsigned char* seckey_to_membuf(size_t *buf_len)
{
	unsigned char *buf, *p;
	size_t len_bytes, vec_size, l1,l2,l3; 
	
	if(!seckey)
		return NULL;

	len_bytes = 0;
	l1 = element_length_in_bytes(seckey->tau);
	l2 = element_length_in_bytes(seckey->beta);
	vec_size = seckey->masterkey.size();
	if(vec_size>0)
		l3 = element_length_in_bytes(seckey->masterkey[0].ver);
	len_bytes =  l1 + l2 + vec_size*l3 + 3 + sizeof(size_t);
	buf = new unsigned char[len_bytes];
	buf[len_bytes-1] = '\0';
	p = buf;

	element_to_bytes(p, seckey->tau);
	p += l1;
	element_to_bytes(p, seckey->beta);
	p += l2;
	*p++ = '\0';

	memcpy(p, &vec_size, sizeof(size_t));
	p += sizeof(size_t);
	*p++ = '\0';

	for(size_t i=0;i<vec_size;i++)
	{	
		element_to_bytes(p, seckey->masterkey[i].ver);
		p += l3;
	}

	*buf_len = len_bytes;
	return buf;
}

void sync_seckey_file()
{
	unsigned char *buf=NULL;
	size_t buf_len=0;
	ofstream f(msk_file, std::ofstream::out|std::ofstream::trunc );
	if(!f.good())
	{
		dprint("Error open secfile\n");
		return ;
	}

	buf = seckey_to_membuf(&buf_len);
	if(!buf){
		return ;
	}
	
	f.write((char*)buf, buf_len);
	delete []buf;
	return ;
}


/*free element in pubkey and seckey*/
static void keys_free()
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

#define NEED_TIME

int main(int argc, char** argv)
{
	parse_args(argc,argv);
#ifdef NEED_TIME
	struct timeval start, end;
	gettimeofday(&start, NULL);
#endif
	setup();
#ifdef NEED_TIME	
	gettimeofday(&end,NULL);
	int ms=0;
	ms += 1000*(end.tv_sec-start.tv_sec);
	ms += (end.tv_usec-start.tv_usec)/1000; 
	cout<<"Time:  "<<ms<<"ms"<<endl;
#endif	

	sync_pubkey_file();
	sync_seckey_file();
	keys_free();
	return 0;
}
