/*
	Tangle - a hash function for the NIST SHA-3 competition
	2008 (c) Rafael Alvarez

	*** This implementation is Little-Endian and should be modified for Big-Endian machines
	*** Uses a 64bit integer for total message size in bits, Tangle supports up to 128 bits for message size


*/

/* size based unsigned integers */
typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
typedef unsigned long long U64;


typedef unsigned char BitSequence;
typedef unsigned long long DataLength; 

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2 } HashReturn;


typedef struct {
	int hashbitlen;				/* digest size in bits */
	U8 rounds;					/* number of rounds */
	U32 H[32];					/* current digest */
	U8  rdata[1024];			/* remaining data */
	U32 rlen;					/* remaining length in bits */
	U64 total;					/* total length in bits */
} hashState;

HashReturn Init(hashState *state, int hashbitlen);
HashReturn Update(hashState *state, const BitSequence *data, DataLength databitlen);
HashReturn Final(hashState *state, BitSequence *hashval);
HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

void Tangle(hashState *state,const BitSequence *message); /* Tangle transform function */
