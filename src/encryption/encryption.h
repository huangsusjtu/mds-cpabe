#ifndef ENCRYPTION
#define ENCRYPTION

#include <glib.h>
#include <pbc.h>
#include <gmp.h>

#include <vector>
using std::vector;
/**/
namespace encryption{
	const size_t max_attr_index = 10000;
	const size_t max_attr_per_file = 100;
	const size_t max_gate_n = 20;
	const size_t max_gate = 100;

	enum TYPE{
		LEAF,
		INTERIOR
	};
	/* interior node in access tree*/
	typedef struct gate_node{
		size_t n,k;
	}gate_node;

	/*leaf node in access tree*/
	typedef struct leaf_node{
		size_t attr_id;
		element_t c1,c2,c3;
	}leaf_node;
	
	/*node in access tree*/
	struct node{
		enum TYPE type;
		element_t s;   //in field
		union{
			struct gate_node g;
			struct leaf_node l;
		};
	};

	/*access tree*/
	typedef  vector<struct node> Policy;
	typedef struct Tree{
		Policy policy;
		size_t gate_num, leaf_num;	
	}Tree;

};

#endif
