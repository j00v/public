// Copyright (c) 2014 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"

#include "hash.h"
#include "uint256.h"

#include <assert.h>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>
#include <sstream>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch)
{
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    std::vector<unsigned char> b256(strlen(psz) * 733 / 1000 + 1); // log(58) / log(256), rounded up.
    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base58 character
        const char* ch = strchr(pszBase58, *psz);
        if (ch == NULL)
            return false;
        // Apply "b256 = b256 * 58 + ch".
        int carry = ch - pszBase58;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); it != b256.rend(); it++) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin();
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

std::string DecodeBase58(const char* psz)
{
    std::vector<unsigned char> vch;
    DecodeBase58(psz, vch);
    std::stringstream ss;
    ss << std::hex;

    for (unsigned int i = 0; i < vch.size(); i++) {
        unsigned char* c = &vch[i];
        ss << setw(2) << setfill('0') << (int)c[0];
    }

    return ss.str();
}

std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    std::vector<unsigned char> b58((pend - pbegin) * 138 / 100 + 1); // log(256) / log(58), rounded up.
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); it != b58.rend(); it++) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        assert(carry == 0);
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin();
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += pszBase58[*(it++)];
    return str;
}

std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}

std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet) ||
        (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, insure it matches the included 4-byte checksum
    uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}

CBase58Data::CBase58Data()
{
    vchVersion.clear();
    vchData.clear();
}

void CBase58Data::SetData(const std::vector<unsigned char>& vchVersionIn, const void* pdata, size_t nSize)
{
    vchVersion = vchVersionIn;
    vchData.resize(nSize);
    if (!vchData.empty())
        memcpy(&vchData[0], pdata, nSize);
}

void CBase58Data::SetData(const std::vector<unsigned char>& vchVersionIn, const unsigned char* pbegin, const unsigned char* pend)
{
    SetData(vchVersionIn, (void*)pbegin, pend - pbegin);
}

bool CBase58Data::SetString(const char* psz, unsigned int nVersionBytes)
{
    std::vector<unsigned char> vchTemp;
    bool rc58 = DecodeBase58Check(psz, vchTemp);
    if ((!rc58) || (vchTemp.size() < nVersionBytes)) {
        vchData.clear();
        vchVersion.clear();
        return false;
    }
    vchVersion.assign(vchTemp.begin(), vchTemp.begin() + nVersionBytes);
    vchData.resize(vchTemp.size() - nVersionBytes);
    if (!vchData.empty())
        memcpy(&vchData[0], &vchTemp[nVersionBytes], vchData.size());
    OPENSSL_cleanse(&vchTemp[0], vchData.size());
    return true;
}

bool CBase58Data::SetString(const std::string& str)
{
    return SetString(str.c_str());
}

std::string CBase58Data::ToString() const
{
    std::vector<unsigned char> vch = vchVersion;
    vch.insert(vch.end(), vchData.begin(), vchData.end());
    return EncodeBase58Check(vch);
}

int CBase58Data::CompareTo(const CBase58Data& b58) const
{
    if (vchVersion < b58.vchVersion)
        return -1;
    if (vchVersion > b58.vchVersion)
        return 1;
    if (vchData < b58.vchData)
        return -1;
    if (vchData > b58.vchData)
        return 1;
    return 0;
}

namespace
{
class CBitcoinAddressVisitor : public boost::static_visitor<bool>
{
private:
    CBitcoinAddress* addr;

public:
    CBitcoinAddressVisitor(CBitcoinAddress* addrIn) : addr(addrIn) {}

    bool operator()(const CKeyID& id) const { return addr->Set(id); }
    bool operator()(const CScriptID& id) const { return addr->Set(id); }
    bool operator()(const CNoDestination& no) const { return false; }
};

} // anon namespace

bool CBitcoinAddress::Set(const CKeyID& id)
{
    SetData(Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS), &id, 20);
    return true;
}

bool CBitcoinAddress::Set(const CScriptID& id)
{
    SetData(Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS), &id, 20);
    return true;
}

bool CBitcoinAddress::Set(const CTxDestination& dest)
{
    return boost::apply_visitor(CBitcoinAddressVisitor(this), dest);
}

bool CBitcoinAddress::IsValid() const
{
    std::string address = ToString();
    // We had exit scam dev wallets to disable
    if (address == "BCcBZ6B5sTtZPS4FhJ2PaToAayNahvKeKb") {
        return false;
    }else if (address == "BN361g4da5japPhLx7wWqc11HxiVPbdyeF") {
        return false;
    }else if (address == "BKKnskrXJHoNGGDcgguWQoWWUi7LjBq13b") {
        return false;
    }else if (address == "BCdxPTgRkypzckZSM4xNMsRELJfCT7nDWF") {
        return false;
    }else if (address == "BGkhUL365iHCkyFW9jEQk8bL25ydNR6sca") {
        return false;
    }else if (address == "BKVdUtiXPMCZAJ7fA5SExkfdDk5eeZEAwy") {
        return false;
    }else if (address == "BSWAQpFvvKLTvhm6SmPFNmKqYChQgBjUBN") {
        return false;
    }else if (address == "B7j6hRMhwFt1XmSgqBKW8Y3X9G9qxF7Ejc") {
        return false;
    }else if (address == "BApTS1gS3sTuLzQxPC7EdowKrM68uMkhML") {
        return false;
    }else if (address == "BTBhrSJ5bogWjgpvyiz7RZ6krnmrt8RsuK") {
        return false;
    }else if (address == "BQVW7gDSvLus3wcrzCfN6ZWERs3buoLdNN") {
        return false;
    }else if (address == "BBtQEdH62gQeqY72qkHohLhfd2DtFcXXbz") {
        return false;
    }else if (address == "BFx4QfBMVCVC114tRNec6QXa7YkbUCTPs6") {
        return false;
    }else if (address == "B6khfsLHp8u3aKwwYPqGxBwW4pkbQSWiJ1") {
        return false;
    }else if (address == "BJoPTtpLC3KGjaKX7TRkqvJj9VwEy1DiYY") {
        return false;
    }else if (address == "BPTJkyTa6i8ugKwBoVPzT6hW9j2Es5H8qZ") {
        return false;
    }else if (address == "BLBBUjqoro3AJLTMrYyog1HrgV7NRaMgZE") {
        return false;
    }else if (address == "B9a7Ghg6XPAiRyV414pGhk8vptFopiqbmk") {
        return false;
    }else if (address == "B75B3UcYRm7We2YnRGPnZuEKWgELqw4pBL") {
        return false;
    }else if (address == "BCFnH2vSJ68ykvttcDm3etU2HYaftVzLr5") {
        return false;
    }else if (address == "B8EmGwSEq1ssYpvpQCQVG6NKDARNKpQ4wP") {
        return false;
    }else if (address == "BHshwsJnbz78uobuNM2witARiAty6BGP2Z") {
        return false;
    }else if (address == "BD5SfecatHpb9UqAQ2Aa7odDMKe7PQ9EnP") {
        return false;
    }else if (address == "BT7HaPWCm8P3LhTDUyqJxMSZakRQAgCnJi") {
        return false;
    }else if (address == "BQe7iKAGtGd8Z94AaXEebBLP3PmHXjk717") {
        return false;
    }else if (address == "BQ1dzMP2q2NgVqVUFqKoRK14jVjw842ew8") {
        return false;
    }else if (address == "BJPXescum2GUaYb94GVDSSZvSth75tPjEj") {
        return false;
    }else if (address == "BA4gm1gUxiua3cqmpPd7XxxGyiPhYp8cYX") {
        return false;
    }else if (address == "BD8AWJfPdPsWdyy7WhYkohVnYP74kbtomH") {
        return false;
    }else if (address == "BR3tfmAbqJoxXMBKHME6VXebFMu3ChQUxC") {
        return false;
    }else if (address == "BNvtKPSaMgbsCFYBaS8TaLjeUD5bw5jkwQ") {
        return false;
    }else if (address == "BEymBACGirRfvmUE883jgyGiaCPzPKMD8p") {
        return false;
    }else if (address == "BRLZzi4oRzwawtQeXJVRRG5rbsusb2Z3wJ") {
        return false;
    }else if (address == "BPr5TUt8jC2LnjcSFn3DGMuRZbDMdrrhgx") {
        return false;
    }else if (address == "BQKEgmKbyRBmNUeZs18k5BkdNtszFPb6uQ") {
        return false;
    }else if (address == "BJhbfUmTcEVaohpdR4cCVHc6WvkF4UFjHc") {
        return false;
    }else if (address == "BBEMde2Ts96YyCbrgaYs3TaCaPuQSq6h9d") {
        return false;
    }else if (address == "BCVVhnq1XPuH3UQy8soSqNjrtNfz9HGQYW") {
        return false;
    }else if (address == "BA8K4Yi9MwrTvasTqf8iYeSyxBKVh5VXc5") {
        return false;
    }else if (address == "B581HmueeRTDVFusZMbnnVcYmdGdauBQJ9") {
        return false;
    }else if (address == "BEdMd2aC1V4zrAjZYBYT6o6sfdcMmEUeSz") {
        return false;
    }else if (address == "BRgbrahbjeuCKz58DKDiJWin8vhSch38Yx") {
        return false;
    }else if (address == "BDzeDLvJZxwF1kNLcTGK3YSYre5MaKA566") {
        return false;
    }else if (address == "B7B1hua6wKzcxYXjz2JpSxdTcS52hkkCBw") {
        return false;
    }else if (address == "BRYhT1HjmgB1i7N56umYgFTrEWbTZUZCay") {
        return false;
    }else if (address == "BDjzrgBzd5yZqQzF3VRLM5BndVFZCEGfhL") {
        return false;
    }else if (address == "BCaMsajgcks9b2Agm8gyxQb6j1mmSSQ4Q4") {
        return false;
    }else if (address == "BK8e3WnvSEXMcCXdFWoyLxZGkJynZnDNKU") {
        return false;
    }else if (address == "BEiJVJfvfY8MDwCA7Zgy6z8RaL6pGwDxpv") {
        return false;
    }else if (address == "B53ZLPzbXftcxV5gQTTRJV4RiA6F3ma77m") {
        return false;
    }    

    return IsValid(Params());
}

bool CBitcoinAddress::IsValid(const CChainParams& params) const
{
    bool fCorrectSize = vchData.size() == 20;
    bool fKnownVersion = vchVersion == params.Base58Prefix(CChainParams::PUBKEY_ADDRESS) ||
                         vchVersion == params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
    return fCorrectSize && fKnownVersion;
}

CTxDestination CBitcoinAddress::Get() const
{
    if (!IsValid())
        return CNoDestination();
    uint160 id;
    memcpy(&id, &vchData[0], 20);
    if (vchVersion == Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS))
        return CKeyID(id);
    else if (vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS))
        return CScriptID(id);
    else
        return CNoDestination();
}

bool CBitcoinAddress::GetKeyID(CKeyID& keyID) const
{
    if (!IsValid() || vchVersion != Params().Base58Prefix(CChainParams::PUBKEY_ADDRESS))
        return false;
    uint160 id;
    memcpy(&id, &vchData[0], 20);
    keyID = CKeyID(id);
    return true;
}

bool CBitcoinAddress::IsScript() const
{
    return IsValid() && vchVersion == Params().Base58Prefix(CChainParams::SCRIPT_ADDRESS);
}

void CBitcoinSecret::SetKey(const CKey& vchSecret)
{
    assert(vchSecret.IsValid());
    SetData(Params().Base58Prefix(CChainParams::SECRET_KEY), vchSecret.begin(), vchSecret.size());
    if (vchSecret.IsCompressed())
        vchData.push_back(1);
}

CKey CBitcoinSecret::GetKey()
{
    CKey ret;
    assert(vchData.size() >= 32);
    ret.Set(vchData.begin(), vchData.begin() + 32, vchData.size() > 32 && vchData[32] == 1);
    return ret;
}

bool CBitcoinSecret::IsValid() const
{
    bool fExpectedFormat = vchData.size() == 32 || (vchData.size() == 33 && vchData[32] == 1);
    bool fCorrectVersion = vchVersion == Params().Base58Prefix(CChainParams::SECRET_KEY);
    return fExpectedFormat && fCorrectVersion;
}

bool CBitcoinSecret::SetString(const char* pszSecret)
{
    return CBase58Data::SetString(pszSecret) && IsValid();
}

bool CBitcoinSecret::SetString(const std::string& strSecret)
{
    return SetString(strSecret.c_str());
}
