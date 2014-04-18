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
#include "decryption.h"
using namespace decryption;

/*gloable variable*/
extern vector< vector<element_t> > matrix;
struct sys_public* pubkey = NULL;
struct sk_user* attr_keys = NULL;

ifstream  file_cipher, user_key;
ofstream file_data;
/**/

/**/
static void fstream_init();
static void fstream_close();

static void load_seckey_from_file();
static void load_cipher_tree();
static void tree_free(struct Tree &tree);

static bool match_attr(struct Tree &tree, struct sk_user &attr_keys);
static bool decrypt_policy(struct Tree &tree);

/**/

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
	file = "README.cipher";
	openfile(file_cipher, file);
	
	file = "README";
	if(file_data.is_open())
		file_data.close();
	file_data.open(file.c_str());
	if(!file.good()){
		std::cerr<<"Err open file"<<std::endl;
		exit(-1);
	}	
}

static void fstream_close()
{
	if(file_ciper.is_open())
		file_cipher.close();
	if(file_data.is_open())
		file_data.close();
	if(user_key.is_open())
		user_key.close();
}

/*user get his secret key from ".sk" file*/
static void load_seckey_from_file()
{
	if(NULL==pubkey)
		pubkey_from_file(pubkey);
	if(NULL != attr_keys)
		return ;
	attr_keys = new struct sk_user;
	element_init_G1( attr_keys->D1, pubkey->p);
	element_init_G1( attr_keys->D2, pubkey->p);
	ifstream f;
	string usename = "alice.sk";
	f.open(usename.c_str());
	if(!f.good()){
		std::cerr<<"Not a good file name"<<std::endl;
		exit(-1);
	}

	size_t l = element_length_in_bytes(attr_keys->D1);
	unsigned char buf[1024];
	unsigned char *p = buf;
	f.read((char*)buf, 2*l+1);
	element_from_bytes( attr_keys->D1, p); p+= l;
	element_from_bytes( attr_keys->D2, p); p+= l;
	
	size_t vec_size;
	f.read((char*)buf, sizeof(size_t)+1 );
	memcpy( &vec_size, buf, sizeof(size_t) );
	assert( vec_size < 1000 );
	
	attr_keys->SK.clear();
	for(size_t i=0; i<vec_size; i++)
	{
		struct userkey tmp;
		f.read((char*)buf, sizeof(size_t)+l1);
		p = buf;
		memcpy( &tmp.attr_id, p , sizeof(size_t)); 
		assert(tmp.attr_id < 1000);
		p += sizeof(size_t);
		element_init_G1( tmp.Di, pubkey->p);
		element_from_bytes( tmp.Di, p);
		attr_keys->SK.push_back(tmp);
	}
	return ;
}

/*read the ciphertext, get the policy of file.  The return value is the number of bytes of the tree in file*/
static size_t load_cipher_tree(struct Tree &tree)
{	
	if(!file_cipher.is_open()){
		std::cerr<<"Need open ciphertext first"<<std::endl;
		exit(-1);
	}
	size_t res =0;
	unsigned char buf[1024];	
	unsigned char *p= buf;
	size_t st = sizeof(size_t);
	file_cipher.read((char*)buf, st*2 );
	res += st*2;
	memcpy( &tree.gate_num, p , st );
	memcpy( &tree.leaf_num, p+st, st);
	assert( tree.gate_num < 100 && tree.leaf_num<100);
	

	Policy &policy = tree.policy;
	policy.clear();
	struct node tmp;
	tmp.recv = 0;
	/*get gate node*/
	size_t len = tree.gate_num*sizeof*2;
	assert( len < 1024);
	file_cipher.read((char*)buf, len);
	res += len;
	size_t i, lchild, rchild;
	lchild = 1;
	p = buf;
	for(i=0;i<tree.gate_num;i++)
	{
		element_init_GT(tmp.euv, pubkey->p);
		struct gate_node &gn = tmp.g;
		memcpy(&gn.n, p, st); p += st;
		memcpy(&gn.k, p, st); p += st;
		assert( gn.k<=gn.n && gn.n<=20 );
		gn.lchild = lchild;
		rchild = lchild + gn.n;
		gn.rchild = rchild-1;
		lchild = rchild;
		policy.push_back(tmp);
	}
	
	/*get leaf node*/
	size_t tlen, l1, l2;
	l1 = element_length_in_bytes(pubkey->g1);
	l2 = element_length_in_bytes(pubkey->g2);
	tlen = st + l1 + 2*l2;
	assert(tlen <1024);
	for(i=0;i<tree.leaf_num;i++)
	{
		file_cipher.read(buf, tlen);
		res += tlen;
		p = buf;

		element_init_GT(tmp.euv, pubkey->p);
		struct leaf_node &ln = tmp.l;
		memcpy(ln.attr_id, p, st); p += st;
		element_init_G2( ln.c1, pubkey->p);
		element_init_G1( ln.c2, pubkey->p);
		element_init_G2( ln.c3, pubkey->p);

		element_from_bytes(ln.c1, p); p += l2;
		element_from_bytes(ln.c2, p); p += l1;
		element_from_bytes(ln.c3, p); p += l2;
		policy.push_back(tmp);
	}
	assert(rchild == policy.size());
	return res ;
}

static void tree_free(struct Tree *tree)
{
	for(size_t i=0;i<tree.gate_num;i++)
	{
		struct node &tmp = tree.policy[i];
		element_clear(tmp.euv);
	}
	for(i = tree.gate_num; i<tree.policy.size(); i++)
	{
		struct node &tmp = tree.policy[i];
		element_clear(tmp.euv);
		element_clear(tmp.l.c1);
		element_clear(tmp.l.c2);
		element_clear(tmp.l.c3);
	}
}

/*test whether this user can decrypt*/
static bool match_attr(struct Tree &tree, struct sk_user &attr_keys)
{	
	Policy& policy = tree.policy;
	element_t t1,t2;
	element_init_GT(t1, pubkey->p);
	element_init_GT(t2, pubkey->p);

	/*for leaf node, pairing operations*/
	for(size_t i=tree.gate_num; i<policy.size(); i++){
		struct node &pn = policy[i];
		struct leaf_node &ln = pn.l;
		element_t tt;
		element_init_GT(tt, pubkey->p);
	
		for(size_t j=0;j<attr_keys.Sk.size(); j++)
		{
			struct userkey &uk = attr_keys.SK[j];
			//if find a attribute match policy
			if(uk.attr_id == ln.attr_id)
			{
				pn.recv = 1;
				element_pairing(t1, ln.c2, pubkey->g2);
				element_pairing(t2, attr_keys.D2, ln.c3);
				element_mul(t1, t1, t2);
				element_pairing(t2, uk.Di, ln.c1);
				element_div(pn.euv, t2, t1);
				break;
			}else
			{
				pn.recv = 0;
			}
		}
	}
	element_clear(t1);
	element_clear(t2);
	/*for gate node, exponential operations*/
	size_t child = attr_keys.SK.size();
	for(size_t i=tree.gate_num-1; i>=0; i--)
	{
		struct node &pn = policy[i];
		struct gate_node &gn = pn.g;
		for(size_t j=gn.lchild; j<=gn.rchild; j++)
		{
			assert(j<policy.size());
			pn.recv += policy[j].recv;
		}
		pn.recv = pn.recv>=gn.k?1:0;
	}
	if(policy[0].recv>0)
		return true;
	return false;
}	



static vector< vector<element_s> > submatrix;
static vector< vector<element_s> > invert_matrix;

/*get a identity matrix of size k*k */
static void get_identity_matrix(struct gate_node &gn)
{
	submatrix.resize(gn.k);
	invert_matrix.resize(gn.k);
	for(size_t i=0;i<gn.k;i++)
	{
		invert_matrix[i].resize(gn.k);
		for(size_t j=0;j<gn.k;j++){
			element_init_GT(&invert_matrix[i][j], pubkey->p);
			if(i==j)
				element_set1(&invert_matrix[i][j]);
			else
				element_set0(&invert_matrix[i][j]);
		}
	}	
}
/*caculate a submatrix of k*k*/
static void get_submatrix(Policy& policy, struct node &pn)
{
	struct gate_node & gn = pn.g;
	assert( pn.recv != 0 );
	vector<int> flag(gn.k, 0);
	for(size_t i=0; i<gn.k; i++)
	{
		/*if the ith child return valid value*/
		if(policy[gn.lchild+i].recv > 0)
		{
			flag[i] = 1;
			submatrix[i] = invert_matrix[i];
			for(size_t t=0;t<gn.k;t++)
			{
				element_init_same_as(submatrix[i][t], invert_matrix[i][t]);
				element_set(submatrix[i][t], invert_matrix[i][t]);
			}
		}
	}
	for(size_t i=gn.k; i<gn.n; i++)
	{
		if(0==policy[gn.lchild+i].recv)
			continue;
		for(size_t j=0;j<gn.k; j++)
		{
			if(0==flag[j]){
				submatrix[j] = matrix[i-gn.k];
				for(size_t t=0; t<gn.k; t++){
					element_init_same_as(submatrix[j][t], matrix[i-gn.k][t]);
					element_set( submatrix[j][t], matrix[i-gn.k][t]);
				}
				flag[j]=1;
			}
		}
	}
}

/*inversion of matrix*/
static void inverse_matrix()
{
	size_t k = submatrix.size();
	for(size_t i=0; i<k; i++)
	{
		for(size_t j=0; j<i ;j++)
		{
			;	
		}
	}
}

/*if gate is AND or OR, use it*/
static void decrypt_gate_and_or(Policy& policy, struct node &np)
{
	struct gate_node &gn = np.g;
	element_set1(np.euv);
	for(size_t i=gn.lchild; i<=gn.rchild; i++)
	{
		if(policy[i].recv>0){
			element_mul( np.euv, np.euv, policy.euv);
		}
	}
}

/**/
static void decrypt_gate(struct Tree& tree)
{
	Policy& policy = tree.policy;
	for(size_t i=tree.gate_num-1; i>=0; i--)
	{
		struct node& pn = policy[i];
		if(0==pn.recv)
			continue;
		struct gate_node &gn = pn.g;
		if(1==gn.k){

		}else if(gn.k == gn.n){
				
		}else{

		}
	}
}



