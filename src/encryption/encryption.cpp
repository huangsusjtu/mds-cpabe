#include <fstream>
using std::ifstream;
using std::ofstream;
#include <string>
using std::string;
#include <iostream>
using std::cout;
using std::cin;
using std::endl;
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <sys/time.h>

#include "syspub.h"
#include "common.h"
#include "encryption.h"
using namespace encryption;

extern vector< vector<element_t> > matrix;
struct sys_public* pubkey = NULL;
ifstream file_rand, file_data, file_attr;
ofstream file_cipher;


static void fstream_init();
static void fstream_close();
static void openfile(ifstream &f, string &file);
void parse_args( int argc, char** argv );
static void  get_policy_from_file(Tree &tree);
static void get_random_key(element_t s);
static void encode_to_children(Policy &policy, size_t pos, size_t child);
static void fill_policy_topdown(Tree &tree);
static struct membuf tree_to_buf(Tree &tree);
static void encrypt_data(unsigned char *key, size_t keylen);
static void tree_to_file(Tree &tree);
static void handle_request();

void Get_MDS_Matrix( struct sys_public *pubkey);


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
	std::cout<<"Encryption ..."<<std::endl;
}


/*open file for filename is (file) */
static void openfile(ifstream &f, string &file)
{
	if(f.is_open())
		f.close();
	f.open(file.c_str());
	if(!f.good())
	{	
		std::cout<<"Err open file"<<std::endl;
		exit(-1);
	}	
	return ;
}

/*open all the file needed*/
static void fstream_init()
{
	string file ="/dev/urandom" ;
	if(!file_rand.is_open()){
		openfile(file_rand, file);
	}

/*open data file*/
//	std::cout<<"Need a data file"<<std::endl;
//	std::cin>>file;
	file = "README";
	openfile(file_data, file);

/*open attr file*/
//	std::cout<<"Need a attribute set file"<<std::endl;
//	std::cin>>file;
	file = "README.attr";
	openfile(file_attr ,file);

/*open ciphertexit*/
	if(file_cipher.is_open())
		file_cipher.close();
	file = "README.cipher";
	file_cipher.open(file.c_str());
	if(!file_cipher.good())
	{	
		std::cout<<"Err open file"<<std::endl;
		exit(-1);
	}	
}

static void fstream_close()
{
	if(file_rand.is_open())
		file_rand.close();
	if(file_attr.is_open())
		file_attr.close();
	if(file_data.is_open())
		file_data.close();
	if(file_cipher.is_open())
		file_cipher.close();
}


/*From attribute set file , construct policy*/
static void  get_policy_from_file(Tree &tree)
{
	if(!pubkey ||!file_attr.is_open())
		return ;
	Policy &policy = tree.policy;

	if(!policy.empty())
		policy.clear();
	size_t num, num_attr, valid=0;

	file_attr >>num>>num_attr;
	if(num > encryption::max_attr_per_file || num_attr > encryption::max_attr_per_file){
		std::cerr<<"Err number of node"<<std::endl;
		exit(-1);
	}

	for(size_t i=0;i<num;i++)
	{
		struct node tmp;
		tmp.type = INTERIOR;
		file_attr >>tmp.g.n>>tmp.g.k;
		if(tmp.g.n<tmp.g.k || tmp.g.n > encryption::max_gate_n){
			std::cerr<<"Err gate parameter"<<std::endl;
			exit(-1);
		}
		valid += tmp.g.n;
		element_init_Zr(tmp.s, pubkey->p);//init secret factor
		policy.push_back(tmp);
	}

//	assert(valid == (num+num_attr-1) );
	if(valid != (num+num_attr-1) )
	{	
		std::cerr<<"Not match nodes and attributes"<<std::endl;
		exit(-1);
	}
	for(size_t i=0;i<num_attr; i++)
	{
		struct node tmp;
		tmp.type = LEAF;
		file_attr >>tmp.l.attr_id;
		if(tmp.l.attr_id > encryption::max_attr_index){
			std::cerr<<"Err attribute parameter"<<std::endl;
			exit(-1);
		}
		element_init_Zr(tmp.s, pubkey->p);
		element_init_G2(tmp.l.c1, pubkey->p);//init public info of leaf node
		element_init_G1(tmp.l.c2, pubkey->p);
		element_init_G2(tmp.l.c3, pubkey->p);
		policy.push_back(tmp);
	}
	tree.gate_num = num;
	tree.leaf_num = num_attr;
	return ;
}

/*Get a random element fron finite field*/
static void get_random_key(element_t s)
{
	//element_init_Zr(s);
	size_t len = element_length_in_bytes(s);
	if(file_rand.is_open())
	{	
		unsigned char *buf = new unsigned char[len+1];
		buf[len] = '\0';
		file_rand.read((char*)buf,len);
		element_from_bytes(s, buf);
		delete []buf;
	}else{
		size_t l = (len+sizeof(int)-1)/sizeof(int);//alignment
		int *buf = new int[l];
		for(size_t i=0; i<l ;i++)
			buf[i] = rand();
		element_from_bytes(s, (unsigned char*)buf);
		delete []buf;
	}
	return ;
}

/*Encode foe a interior node */
static void encode_to_children(Policy &policy, size_t pos, size_t child)
{
	struct node &node_ref = policy[pos];
	struct gate_node &gate = node_ref.g;
	
	element_t tmp;
	element_init_Zr(tmp, pubkey->p);
	element_set0(tmp);
	size_t i =0;
	/*For systemmatic encode*/
	vector<element_s> source;
	for(; i<gate.k-1; i++)
	{
		get_random_key(policy[child+i].s);
		element_add(tmp, tmp, policy[child+i].s);
		source.push_back( *(policy[child+i].s) );
	}
	element_sub(policy[child+i].s, node_ref.s, tmp);
	source.push_back( *(policy[child+i].s) );
	
	/*cauchy encode*/
	for(i=gate.k; i<gate.n; i++)
	{
		vec_mul(policy[child+i].s , source, i-gate.k, pubkey);
	}
}

/*input is access tree and the node (pos), and secret value (s)*/
static void fill_policy_topdown(Tree &tree)
{
	if(!pubkey){
		std::cerr<<"Not init pubkey"<<std::endl;
		return ;
	}
	Policy &policy = tree.policy;
	size_t child = 1;
	for(size_t pos=0; pos<policy.size(); pos++)
	{
		struct node &node_ref = policy[pos]; 

		/*for leaf node*/
		if(node_ref.type == LEAF){
			struct leaf_node &leaf = node_ref.l;  //ref of leaf node
			struct attr_pub &attr_ref = pubkey->pubkey[leaf.attr_id];  //ref of public key in system public info	

			element_pow_zn(leaf.c1, pubkey->g2, node_ref.s);
			element_pow_zn(leaf.c2, attr_ref.T, node_ref.s);
			element_pow_zn(leaf.c3, attr_ref.Version , node_ref.s);
			element_div(leaf.c3 , leaf.c3, leaf.c1);
		}/*for gate node*/
		else if(node_ref.type == INTERIOR){
			encode_to_children(policy, pos, child);
			child += node_ref.g.n;
		}
	}	
}

/*translate Policy to membuf,  destory the tree*/
static struct membuf tree_to_buf(Tree &tree)
{
	struct membuf mem_tree;
	unsigned char *p;
	size_t l1,l2;
	l1 = element_length_in_bytes( pubkey->g1 );
	l2 = element_length_in_bytes( pubkey->g2 );
	mem_tree.len = 1 + sizeof(size_t)*2 + tree.gate_num*(2*sizeof(size_t)) + tree.leaf_num*(sizeof(size_t)+ l1+2*l2);
	mem_tree.buf = new unsigned char[mem_tree.len];
	p = mem_tree.buf;
	p[mem_tree.len-1] = '\0';
	memcpy(p, &tree.gate_num, sizeof(size_t)); p+=sizeof(size_t);
	memcpy(p, &tree.leaf_num, sizeof(size_t)); p+=sizeof(size_t);
	Policy &policy = tree.policy;
	size_t i=0;
	for(;i<tree.gate_num;i++)
	{
		assert( policy[i].type == INTERIOR);
		memcpy(p, &policy[i].g.n, sizeof(size_t));
		p += sizeof(size_t);
		memcpy(p, &policy[i].g.k, sizeof(size_t));
		p += sizeof(size_t);
	}
	while(i<policy.size())
	{
		assert( policy[i].type == LEAF);
		memcpy(p, &policy[i].l.attr_id, sizeof(size_t));
		p += sizeof(size_t);
		element_to_bytes(p, policy[i].l.c1);
		p += l2;
		element_to_bytes(p, policy[i].l.c2);
		p += l1;
		element_to_bytes(p , policy[i].l.c3);
		p += l2;
		i++;
		assert( p-mem_tree.buf < mem_tree.len);
	//	printf("%d  ", p-mem_tree.buf);
	//	printf("%d\n", mem_tree.len);
	}
	return mem_tree;
}

static void encrypt_data(unsigned char *key, size_t keylen)
{
	assert(keylen<1000);
	/*file size*/
	size_t filelen, used;
	file_data.seekg(0, file_data.end);
	filelen = file_data.tellg();
	file_data.seekg(0, file_data.beg);
	
	unsigned char *buf = new unsigned char[keylen];
	while(!file_data.eof()){
		file_data.read((char*)buf, keylen);
		used = filelen>keylen? keylen:filelen;
		for(size_t i = 0;i<used;i++)
			buf[i] ^= key[i];
		file_cipher.write((char*)buf, used);
	}
	return ;
}

static void tree_to_file(Tree &tree)
{
	struct membuf p = tree_to_buf(tree);
	file_cipher.write((char*)p.buf, p.len);
	delete []p.buf;
}

static void handle_request()
{
	Tree tree;
	Policy &policy = tree.policy;
	/*init stream to read file data and file file attributes*/	
	fstream_init();
	/*read access policy from file*/
	get_policy_from_file(tree);
	if(policy.size()==0){
		std::cerr<<"Empty policy"<<std::endl;
		exit(-1);
	}
	/*Get a random key to encrypt file data*/
	element_s *r = policy[0].s;
	get_random_key(r);

struct timeval start, end;
gettimeofday(&start, NULL);
	/*encrypt the random key by fill_policy_topdown, and write to file*/
	fill_policy_topdown(tree);
gettimeofday(&end, NULL);
printf("%d ms", end.tv_usec-start.tv_usec);	

	tree_to_file(tree);

	/*encrypt file data and flush to file*/
	size_t len = element_length_in_bytes(r);
	unsigned char *buf = new unsigned char[len];
	element_to_bytes(buf, r);
	encrypt_data(buf, len);
	delete []buf;
	/*fstream close*/
	fstream_close();
}


int main(int argc , char** argv)
{
	parse_args(argc, argv);

	/*we need public keys from file*/
	pubkey_from_file(pubkey);	
	Get_MDS_Matrix( pubkey);
	
	/*encrypt one file is one request*/
	handle_request();

	/*free public parameter */
	keys_free(pubkey, NULL);
	/**/
	return 0;
}











