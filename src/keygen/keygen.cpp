#include <cassert>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <string>
#include <fstream>
using std::ifstream;
using std::ofstream;
using std::string;
#include "common.h"
#include "syspub.h"


const char* usage =
"Usage: keygen [OPTION ...]\n"
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



extern struct sys_secret* seckey ;
extern struct sys_public* pubkey ;

static void parse_args( int argc, char** argv );
static char* GetRequest_from_file(string filename);
static void handle_request();


static void parse_args( int argc, char** argv )
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


static char* GetRequest_from_file(string filename)
{
	/*open user attribute file */
	ifstream f(filename.c_str());
	if(!f.good()){
		dprint("Invalid filename!\n");
		exit(-1);
	}

	/*read attribute file and generate secret key*/
	size_t l1,l2, l3, vec_size, len_bytes;
	size_t index, maxindex = seckey->masterkey.size();
	element_t D1,D2, Di, uj, uV ,var1;
	
	
	element_init_G1(D1, pubkey->p);
	element_init_G1(D2, pubkey->p);
	element_init_G1(Di, pubkey->p);
	l1 = element_length_in_bytes(D1);
	l2 = element_length_in_bytes(D2);
	l3 = element_length_in_bytes(Di);
	

	element_init_Zr(var1, pubkey->p);
	element_init_Zr(uV, pubkey->p);
	element_init_Zr(uj, pubkey->p);
	element_from_string( uj , const_cast<char*>(filename.c_str()) );
	
	
	element_add(var1, uj, seckey->tau);

	element_mul(var1, var1, seckey->beta);
	element_pow_zn(D1, pubkey->g1, var1);
	element_pow_zn(D2, pubkey->g1, uj);
	
	f>>vec_size;
	assert( vec_size<10000 );
	len_bytes = l1 + l2 + sizeof(size_t) + vec_size*l3 + 3; // contains '\n'
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
		assert(index<maxindex);
	
		if(index>maxindex)
			continue ;
		index--;
		
		element_mul(uV, uj, seckey->masterkey[index].ver);
		element_pow_zn(D1, pubkey->g1, uV);
		element_mul(Di, D1, pubkey->pubkey[index].T);
		element_to_bytes( p, Di);
		p += l3;
	}
	
		
	element_clear(D1);
	element_clear(D2);
	element_clear(var1);


	element_clear(uj);
	element_clear(uV);
	element_clear(Di);

	return (char*)buf;
}

/*handle request from file*/
static void handle_request()
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

	
	if(!buf){
		dprint("Get request from file err \n");
		return ;
	}
	size_t len = strlen(buf);

	/*create user secret key file*/
	string key_filename(filename);
	key_filename +=".sk";
	ofstream of(key_filename.c_str());
	if(!of.good()){
		dprint("Err create secret key file\n");
		delete []buf;
		return ;
	}
	
	of.write(buf, len);
	delete []buf;
	return ;
}







#define NEED_TIME

int main(int argc, char** argv)
{
	parse_args(argc, argv);
	
	pubkey_from_file(pubkey);
	seckey_from_file(seckey, pubkey->p);

	handle_request();
	keys_free(pubkey, seckey);

	return 0;
}






