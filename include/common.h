#ifndef COMMON
#define COMMON

#include "syspub.h"

#define debug

#ifdef debug
#define dprint printf
#endif

typedef struct membuf{
	unsigned char *buf;
	size_t len ;
	membuf():buf(NULL),len(0){};
}membuf;


void element_from_string( element_t h, char* s );

void pubkey_from_file(struct sys_public *&pubkey);
void seckey_from_file(struct sys_secret *&seckey, pairing_t p);

void keys_free(struct sys_public *pubkey, struct sys_secret *seckey);

void Get_MDS_Matrix( struct sys_public *pubkey);
void vec_mul(element_t res,  vector<element_s> &source,  size_t column,  struct sys_public *pubkey);

 #endif
