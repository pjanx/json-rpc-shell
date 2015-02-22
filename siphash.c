// Code taken from https://github.com/floodyberry/siphash with some edits.
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

#include "siphash.h"

inline static uint64_t
u8to64_le (const unsigned char *p)
{
	return
		(uint64_t) p[0]       |
		(uint64_t) p[1] <<  8 |
		(uint64_t) p[2] << 16 |
		(uint64_t) p[3] << 24 |
		(uint64_t) p[4] << 32 |
		(uint64_t) p[5] << 40 |
		(uint64_t) p[6] << 48 |
		(uint64_t) p[7] << 56 ;
}

uint64_t
siphash (const unsigned char key[16], const unsigned char *m, size_t len)
{
	uint64_t v0, v1, v2, v3;
	uint64_t mi, k0, k1;
	uint64_t last7;
	size_t i, blocks;

	k0 = u8to64_le (key + 0);
	k1 = u8to64_le (key + 8);
	v0 = k0 ^ 0x736f6d6570736575ull;
	v1 = k1 ^ 0x646f72616e646f6dull;
	v2 = k0 ^ 0x6c7967656e657261ull;
	v3 = k1 ^ 0x7465646279746573ull;

	last7 = (uint64_t) (len & 0xff) << 56;

#define ROTL64(a,b) (((a)<<(b))|((a)>>(64-b)))

#define COMPRESS                              \
	v0 += v1; v2 += v3;                       \
	v1 = ROTL64 (v1,13); v3 = ROTL64 (v3,16); \
	v1 ^= v0; v3 ^= v2;                       \
	v0 = ROTL64 (v0,32);                      \
	v2 += v1; v0 += v3;                       \
	v1 = ROTL64 (v1,17); v3 = ROTL64 (v3,21); \
	v1 ^= v2; v3 ^= v0;                       \
	v2 = ROTL64(v2,32);

	for (i = 0, blocks = (len & ~(size_t) 7); i < blocks; i += 8)
	{
		mi = u8to64_le (m + i);
		v3 ^= mi;
		COMPRESS
		COMPRESS
		v0 ^= mi;
	}

	switch (len - blocks)
	{
	case 7: last7 |= (uint64_t) m[i + 6] << 48;
	case 6: last7 |= (uint64_t) m[i + 5] << 40;
	case 5: last7 |= (uint64_t) m[i + 4] << 32;
	case 4: last7 |= (uint64_t) m[i + 3] << 24;
	case 3: last7 |= (uint64_t) m[i + 2] << 16;
	case 2: last7 |= (uint64_t) m[i + 1] <<  8;
	case 1: last7 |= (uint64_t) m[i + 0]      ;
	default:;
	};
	v3 ^= last7;
	COMPRESS
	COMPRESS
	v0 ^= last7;
	v2 ^= 0xff;
	COMPRESS
	COMPRESS
	COMPRESS
	COMPRESS

	return v0 ^ v1 ^ v2 ^ v3;
}

