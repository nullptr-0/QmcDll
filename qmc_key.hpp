#include"TencentTea.hpp"
#include "base64.hpp"

void simpleMakeKey(uint8_t salt, int length, std::vector<uint8_t> &key_buf) {
    for (size_t i = 0; i < length; ++i) {
        double tmp = tan((float)salt + (double)i * 0.1);
        key_buf[i] = 0xFF & (uint8_t)(fabs(tmp) * 100.0);
    }
}

bool QmcDecryptKey(std::vector<uint8_t> raw, std::vector<uint8_t> &outVec) {
    std::vector<uint8_t> rawDec;
    rawDec.resize(base64::decoded_size(raw.size()));
    auto n = base64::decode(rawDec.data(), (const char*)(raw.data()), raw.size()).first;
    if (n < 16) {
        return false;
        //key length is too short
    }
    rawDec.resize(n);

    std::vector<uint8_t> simpleKey;
    simpleKey.resize(8);
    simpleMakeKey(106, 8, simpleKey);
    std::vector<uint8_t> teaKey;
    teaKey.resize(16);
    for (size_t i = 0; i < 8; i++) {
        teaKey[i << 1] = simpleKey[i];
        teaKey[(i << 1) + 1] = rawDec[i];
    }
    std::vector<uint8_t> out;
    std::vector<uint8_t> tmpRaw;
    tmpRaw.resize(rawDec.size() - 8);
    for (size_t i = 0; i < tmpRaw.size(); i++)
    {
        tmpRaw[i] = rawDec[8 + i];
    }
    if (decryptTencentTea(tmpRaw, teaKey, out))
    {
        rawDec.resize(8 + out.size());
        for (size_t i = 0; i < out.size(); i++)
        {
            rawDec[8 + i] = out[i];
        }
        outVec = rawDec;
        return true;
    }
    else
    {
        return false;
    }
}

bool QmcEncryptKey(std::vector<uint8_t> raw, std::vector<uint8_t>& outVec) {
    std::vector<uint8_t> simpleKey;
    simpleKey.resize(8);
    simpleMakeKey(106, 8, simpleKey);
    std::vector<uint8_t> teaKey;
    teaKey.resize(16);
    for (size_t i = 0; i < 8; i++) {
        teaKey[i << 1] = simpleKey[i];
        teaKey[(i << 1) + 1] = raw[i];
    }
    std::vector<uint8_t> out;
    out.resize(raw.size() - 8);
    for (size_t i = 0; i < out.size(); i++)
    {
        out[i] = raw[8 + i];
    }
    std::vector<uint8_t> tmpRaw;
    if (encryptTencentTea(out, teaKey, tmpRaw))
    {
        raw.resize(tmpRaw.size() + 8);
        for (size_t i = 0; i < tmpRaw.size(); i++)
        {
            raw[i + 8] = tmpRaw[i];
        }
        std::vector<uint8_t> rawEnc;
        rawEnc.resize(base64::encoded_size(raw.size()));
        auto n = base64::encode(rawEnc.data(), (const char*)(raw.data()), raw.size());
        rawEnc.resize(n);
        outVec = rawEnc;
        return true;
    }
    else
    {
        return false;
    }
}
