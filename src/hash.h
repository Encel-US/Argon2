// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include "uint256.h"
#include "serialize.h"
#include "hash/ar2/src/argon2.h"
extern "C" {
#include "hash/scrypt-jane/scrypt-jane.h"
}
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>
#include <string>

template<typename T1>
inline uint256 hashArgon2(const T1 pbegin, const T1 pend)
{
 static unsigned char pblank[1];
uint256 hash1,hash2,hash3;

 uint256 mask = 8;
 uint256 zero = 0;
 unsigned int t_costs = 2;            
 unsigned int m_costs = 16;
 
scrypt((pbegin == pend ? pblank : (const unsigned char*)(&pbegin[0])),(pend - pbegin) * sizeof(pbegin[0]),
		(pbegin == pend ? pblank : (const unsigned char*)(&pbegin[0])),(pend - pbegin) * sizeof(pbegin[0]),       
        m_costs/2, 0, 0,(unsigned char*)(&hash1), 32);

	if ((hash1 & mask) != zero)
   hash_argon2d(static_cast<void*>(&hash2), 32, static_cast<void*>(&hash1), 32,
                 static_cast<void*>(&hash1), 32,  t_costs, m_costs);			 
	else
   hash_argon2i(static_cast<void*>(&hash2), 32, static_cast<void*>(&hash1), 32,
                 static_cast<void*>(&hash1), 32,  t_costs, m_costs);	
   
scrypt((unsigned char*)(&hash2),32,
	    (unsigned char*)(&hash2),32,       
        m_costs/2, 0, 0,(unsigned char*)(&hash3), 32);

    return hash3;   
}

class CHashWriter
{
private:
    SHA256_CTX ctx;

public:
    int nType;
    int nVersion;

    void Init() {
        SHA256_Init(&ctx);
    }

    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {
        Init();
    }

    CHashWriter& write(const char *pch, size_t size) {
        SHA256_Update(&ctx, pch, size);
        return (*this);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 hash1;
        SHA256_Final((unsigned char*)&hash1, &ctx);
        return hash1;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};

template<typename T1, typename T2>
inline uint256 Hash4(const T1 p1begin, const T1 p1end,
                    const T2 p2begin, const T2 p2end)
{
    static unsigned char pblank[1];
    uint256 hash1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (p1begin == p1end ? pblank : (unsigned char*)&p1begin[0]), (p1end - p1begin) * sizeof(p1begin[0]));
    SHA256_Update(&ctx, (p2begin == p2end ? pblank : (unsigned char*)&p2begin[0]), (p2end - p2begin) * sizeof(p2begin[0]));
    SHA256_Final((unsigned char*)&hash1, &ctx);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
    uint256 hash1;
    SHA256(&vch[0], vch.size(), (unsigned char*)&hash1);
    uint160 hash2;
    RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash);

#endif
