#include <iostream>
#include <fstream>
#include <cmath>
#include <sstream>
#include <vector>
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#include "qmc_key.hpp"
#include "qmc_cipher.hpp"

#define MAX_PATH 260

size_t encSuccess = 0;
size_t encFailure = 0;

size_t decSuccess = 0;
size_t decFailure = 0;

size_t fileSizeG(std::ifstream& file)
{
    file.seekg(0, std::ios::end);
    size_t fs = (size_t)file.tellg();
    file.seekg(0, std::ios::beg);
    return fs;
}

class QmcDecode {
private:
    std::ifstream f;
    std::string fileName = "";
    std::string pswFileName = "";

    std::vector<uint8_t> rawKeyBuf;
    std::string cipherType = "";

    size_t dataSize = 0;
    size_t keySize = 0;
    int rawKeyField2{};
    int rawKeyField3{};

    std::string typeViaExt(std::string fn)
    {
        if (fn.find(".qmc") < fn.size() || fn.find(".m") < fn.size())
        {
            std::cout << "Type is recognized as normal." << std::endl;
            return "normal";
        }
        else if (fn.find(".cache") < fn.size())
        {
            std::cout << "Type is recognized as cache(Result can be either plaintext or ciphertext.)." << std::endl;
            return "cache";
        }
        else if (fn.find(".tm") < fn.size())
        {
            std::cout << "Type is recognized as IOS download." << std::endl;
            return "ios";
        }
        else
        {
            std::cout << "Type cannot be recognized. Please check your file name." << std::endl;
            return "invalid";
        }
    }

    std::string extViaExt(std::string fn)
    {
        if (fn.find(".m") < fn.size())
        {
            return "." + fileName.substr(2 + fileName.find_last_of("."));
        }
        else if (fn.find(".qmc") < fn.size())
        {
            return "." + fileName.substr(4 + fileName.find_last_of("."));
        }
        else if (fn.find(".tm") < fn.size())
        {
            return "." + fileName.substr(3 + fileName.find_last_of("."));
        }
        else
        {
            return ".bin";
        }
    }

    std::string checkType() {
        if (pswFileName != "")
        {
            f.close();
            f.open(pswFileName, std::ios::in | std::ios::binary);
        }
        f.seekg(-4, std::ios::end);
        std::ostringstream buf_tag;
        buf_tag.width(4);
        buf_tag << f.rdbuf();
        if (buf_tag.str() == "QTag")
        {
            if (pswFileName != "")
            {
                f.close();
                f.open(fileName, std::ios::in | std::ios::binary);
            }
            return "QTag";
        }
        else if (buf_tag.str() == "STag")
        {
            if (pswFileName != "")
            {
                f.close();
                f.open(fileName, std::ios::in | std::ios::binary);
            }
            return "STag";
        }
        else
        {
            keySize = (*(uint32_t*)(buf_tag.str().data()));
            if (keySize < 0x400)
            {
                if (pswFileName != "")
                {
                    f.close();
                    f.open(fileName, std::ios::in | std::ios::binary);
                }
                return "Map/RC4";
            }
            else
            {
                if (pswFileName != "")
                {
                    f.close();
                    f.open(fileName, std::ios::in | std::ios::binary);
                }
                return "Static";
            }
        }
    }

    bool readRawKeyQTag() {
        // get raw key data length
        if (pswFileName!="")
        {
            f.close();
            f.open(pswFileName, std::ios::in | std::ios::binary);
        }
        f.seekg(-8, std::ios::end);
        if (f.fail())return false;

        char data_len_buf[sizeof(long)]{};
        f.read(data_len_buf, 4);
        if (f.fail())return false;

        long data_len = ntohl(*((uint32_t*)data_len_buf));
        f.seekg(-(8 + data_len), std::ios::end);
        if (f.fail())return false;

        rawKeyBuf.resize(data_len);
        f.read((char*)(rawKeyBuf.data()), data_len);
        if (f.fail()) return false;

        if (pswFileName != "")
        {
            f.close();
            f.open(fileName, std::ios::in | std::ios::binary);
            this->dataSize = fileSizeG(f);
        }
        else
        {
            this->dataSize = fileSizeG(f) - (8 + data_len);
        }
        return true;
    }

    bool parseRawKeyQTag() {
        std::vector<std::string> items;
        items.resize(3);
        int index = 2;
        for (int i = rawKeyBuf.size() - 1; i >= 0; i--)
        {
            if (rawKeyBuf[i] == ',')
            {
                if (index == 1)
                {
                    rawKeyBuf.resize(i);
                }
                index--;
                if (index < 0)
                {
                    return false;
                }
            }
            else
            {
                items[index] = (char)rawKeyBuf[i] + items[index];
            }
        }
        this->rawKeyField2 = std::stoi(items[1]);
        this->rawKeyField3 = std::stoi(items[2]);
        return true;
    }

    bool readRawKeyNoQTag() {
        // get raw key data length
        if (pswFileName != "")
        {
            f.close();
            f.open(pswFileName, std::ios::in | std::ios::binary);
        }
        f.seekg(-(4 + (int)keySize), std::ios::end);
        if (f.fail())return false;

        rawKeyBuf.resize(keySize);
        f.read((char*)(rawKeyBuf.data()), keySize);
        if (f.fail()) return false;

        if (pswFileName != "")
        {
            f.close();
            f.open(fileName, std::ios::in | std::ios::binary);
            this->dataSize = fileSizeG(f);
        }
        else
        {
            this->dataSize = fileSizeG(f) - 4 - keySize;
        }
        return true;
    }

    void DecodeStatic();

    void DecodeMapRC4();

    void DecodeCache();

    void DecodeTm();

public:
    explicit QmcDecode(const char* file_name, const char* psw_fn) {
        fileName = file_name;
        pswFileName = psw_fn;
        f.open(file_name, std::ios::in | std::ios::binary);
        if (f.fail()) {
            std::cout << "open file failed" << std::endl;
            decFailure++;
            return;
        }
        std::string type = typeViaExt(fileName);
        if (type == "normal")
        {
            std::string fileType = checkType();
            if (fileType == "QTag") {
                std::cout << "file with QTag" << std::endl;
                if (!readRawKeyQTag()) {
                    std::cout << "file is invalid (read raw key data failed)" << std::endl;
                    decFailure++;
                    return;
                }
                if (!parseRawKeyQTag()) {
                    std::cout << "file is invalid (parse raw key data failed)" << std::endl;
                    decFailure++;
                    return;
                }
                fileType = "Map/RC4";
            }
            else if (fileType == "Map/RC4") {
                std::cout << "file with no QTag(using Map/RC4)" << std::endl;
                if (!readRawKeyNoQTag()) {
                    std::cout << "file is invalid (read raw key data failed)" << std::endl;
                    decFailure++;
                    return;
                }
            }
            else if (fileType == "Static") {
                std::cout << "file with no QTag(using Static) or invalid" << std::endl;
            }
            else {
                std::cout << "file with STag(No Embedded Key. Please downgrade your app.)" << std::endl;
                decFailure++;
                return;
            }
            cipherType = fileType;
        }
        else
        {
            cipherType = type;
        }
    }

    explicit QmcDecode(const char *file_name) {
        fileName = file_name;
        f.open(file_name, std::ios::in | std::ios::binary);
        if (f.fail()) {
            std::cout << "open file failed" << std::endl;
            decFailure++;
            return;
        }
        std::string type = typeViaExt(fileName);
        if (type == "normal")
        {
            std::string fileType = checkType();
            if (fileType == "QTag") {
                std::cout << "file with QTag" << std::endl;
                if (!readRawKeyQTag()) {
                    std::cout << "file is invalid (read raw key data failed)" << std::endl;
                    decFailure++;
                    return;
                }
                if (!parseRawKeyQTag()) {
                    std::cout << "file is invalid (parse raw key data failed)" << std::endl;
                    decFailure++;
                    return;
                }
                fileType = "Map/RC4";
            }
            else if (fileType == "Map/RC4") {
                std::cout << "file with no QTag(using Map/RC4)" << std::endl;
                if (!readRawKeyNoQTag()) {
                    std::cout << "file is invalid (read raw key data failed)" << std::endl;
                    decFailure++;
                    return;
                }
            }
            else if (fileType == "Static") {
                std::cout << "file with no QTag(using Static) or invalid" << std::endl;
            }
            else {
                std::cout << "file with STag(No Embedded Key. Please downgrade your app.)" << std::endl;
                decFailure++;
                return;
            }
            cipherType = fileType;
        }
        else
        {
            cipherType = type;
        }
    }

    ~QmcDecode() {
        f.close();
    }

    void Decode();
};

void QmcDecode::DecodeStatic()
{
    QmcStaticCipher sc;
    std::vector<uint8_t> v;
    v.resize(fileSizeG(f));
    f.seekg(0, std::ios::beg);
    if (f.fail())
    {
        decFailure++;
        return;
    }
    f.read((char*)v.data(), v.size());
    if (f.fail())
    {
        decFailure++;
        return;
    }
    sc.proc(v, 0);
    std::string fn = fileName.substr(0, fileName.find_last_of(".")) + extViaExt(fileName);
    std::cout << "Output:\n" << fn << std::endl;
    std::ofstream of(fn, std::ios::out | std::ios::binary | std::ios::trunc);
    of.write((char*)v.data(), v.size());
    decSuccess++;
}

void QmcDecode::DecodeMapRC4() {
    std::vector<uint8_t> out;
    if (!QmcDecryptKey(rawKeyBuf, out))
    {
        std::cout << "file is not supported(New Embedded Key format. Please downgrade your app.)" << std::endl;
        decFailure++;
        return;
    }

    std::vector<uint8_t> v;
    v.resize(this->dataSize);
    f.seekg(0, std::ios::beg);
    if (f.fail())
    {
        decFailure++;
        return;
    }
    f.read((char*)v.data(), this->dataSize);
    if (f.fail())
    {
        decFailure++;
        return;
    }

    if (out.size() > 300)
    {
        QmcRC4Cipher c(out, 2);
        c.proc(v, 0);
    }
    else
    {
        QmcMapCipher c(out, 2);
        c.proc(v, 0);
    }

    std::string fn = fileName.substr(0, fileName.find_last_of(".")) + extViaExt(fileName);
    std::cout << "Output:\n" << fn << std::endl;
    std::ofstream of(fn, std::ios::out | std::ios::binary | std::ios::trunc);
    of.write((char*)v.data(), this->dataSize);
    decSuccess++;
}

void QmcDecode::DecodeCache()
{
    std::vector<uint8_t> v;
    v.resize(fileSizeG(f));
    f.seekg(0, std::ios::beg);
    if (f.fail())
    {
        decFailure++;
        return;
    }
    f.read((char*)v.data(), v.size());
    if (f.fail())
    {
        decFailure++;
        return;
    }
    for (size_t i = 0; i < v.size(); i++) {
        v[i] ^= 0xf4;
        if (v[i] <= 0x3f) v[i] = v[i] * 4;
        else if (v[i] <= 0x7f) v[i] = (v[i] - 0x40) * 4 + 1;
        else if (v[i] <= 0xbf) v[i] = (v[i] - 0x80) * 4 + 2;
        else v[i] = (v[i] - 0xc0) * 4 + 3;
    }
    std::string fn = fileName.substr(0, fileName.find_last_of(".")) + extViaExt(fileName);
    std::cout << "Output:\n" << fn << std::endl;
    std::ofstream of(fn, std::ios::out | std::ios::binary | std::ios::trunc);
    of.write((char*)v.data(), v.size());
    decSuccess++;
}

void QmcDecode::DecodeTm()
{
    uint8_t const TM_HEADER[] = { 0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70 };
    std::vector<uint8_t> v;
    v.resize(fileSizeG(f));
    f.seekg(0, std::ios::beg);
    if (f.fail())
    {
        decFailure++;
        return;
    }
    f.read((char*)v.data(), v.size());
    if (f.fail())
    {
        decFailure++;
        return;
    }
    for (size_t cur = 0; cur < 8; cur++) {
        v[cur] = TM_HEADER[cur];
    }
    std::string fn = fileName.substr(0, fileName.find_last_of(".")) + extViaExt(fileName);
    std::cout << "Output:\n" << fn << std::endl;
    std::ofstream of(fn, std::ios::out | std::ios::binary | std::ios::trunc);
    of.write((char*)v.data(), v.size());
    decSuccess++;
}

void QmcDecode::Decode()
{
    if (cipherType == "Map/RC4")
    {
        DecodeMapRC4();
    }
    else if (cipherType == "Static")
    {
        DecodeStatic();
    }
    else if (cipherType == "cache")
    {
        DecodeCache();
    }
    else if (cipherType == "ios")
    {
        DecodeTm();
    }
    else {
        std::cout << "File is invalid or encryption type is not supported." << std::endl;
        std::cin.get();
    }
}

class QmcEncode {
private:
    std::ifstream f;
    std::string fileName = "";
    std::string pswFileName = "";
    std::string ext = "";

    std::vector<uint8_t> rawKeyBuf;
    std::string cipherType = "";

    void EncodeStatic();

    void EncodeMapRC4();

    void EncodeCache();

    void EncodeTm();

public:
    explicit QmcEncode(const char* file_name, const char* psw_fn, std::string type) {
        fileName = file_name;
        pswFileName = psw_fn;
        f.open(file_name, std::ios::in | std::ios::binary);
        if (f.fail()) {
            std::cout << "open file failed" << std::endl;
            encFailure++;
            return;
        }
        ext = fileName.substr(1 + fileName.find_last_of("."));
        cipherType = type;
    }

    explicit QmcEncode(const char* file_name, std::string type) {
        fileName = file_name;
        f.open(file_name, std::ios::in | std::ios::binary);
        if (f.fail()) {
            std::cout << "open file failed" << std::endl;
            encFailure++;
            return;
        }
        ext = fileName.substr(1 + fileName.find_last_of("."));
        cipherType = type;
    }

    ~QmcEncode() {
        f.close();
    }

    void Encode();
};

void QmcEncode::EncodeStatic()
{
    QmcStaticCipher sc;
    std::vector<uint8_t> v;
    v.resize(fileSizeG(f));
    f.seekg(0, std::ios::beg);
    if (f.fail())
    {
        encFailure++;
        return;
    }
    f.read((char*)v.data(), v.size());
    if (f.fail())
    {
        encFailure++;
        return;
    }
    sc.proc(v, 0);
    std::string fn = fileName.substr(0, fileName.find_last_of(".")) + ".qmc" + ext;
    std::cout << "Output:\n" << fn << std::endl;
    std::ofstream of(fn, std::ios::out | std::ios::binary | std::ios::trunc);
    of.write((char*)v.data(), v.size());
    encSuccess++;
}

void QmcEncode::EncodeMapRC4() {
    srand(time(0));
    std::vector<uint8_t> v;
    v.resize(fileSizeG(f));
    f.seekg(0, std::ios::beg);
    if (f.fail())
    {
        encFailure++;
        return;
    }
    f.read((char*)v.data(), v.size());
    if (f.fail())
    {
        encFailure++;
        return;
    }

    std::vector<uint8_t> out;
    if (cipherType == "RC4")
    {
        QmcRC4Cipher c(out, 1);
        c.proc(v, 0);
    }
    else if (cipherType == "Map")
    {
        QmcMapCipher c(out, 1);
        c.proc(v, 0);
    }
    else if (cipherType == "QTag")
    {
        if (rand() % 2 == 0)
        {
            QmcRC4Cipher c(out, 1);
            c.proc(v, 0);
        }
        else
        {
            QmcMapCipher c(out, 1);
            c.proc(v, 0);
        }
    }
    else
    {
        encFailure++;
        return;
    }

    if (!QmcEncryptKey(out, rawKeyBuf, rand() % 2))
    {
        std::cout << "Key encryption failed." << std::endl;
        encFailure++;
        return;
    }
    if (cipherType == "QTag")
    {
        rawKeyBuf.push_back(',');
        rawKeyBuf.push_back('0');
        rawKeyBuf.push_back(',');
        rawKeyBuf.push_back('2');
    }

    std::string fn = fileName.substr(0, fileName.find_last_of(".")) + ".m" + ext;
    std::cout << "Output:\n" << fn << std::endl;
    std::ofstream of(fn, std::ios::out | std::ios::binary);
    of.write((char*)v.data(), v.size());
    if (pswFileName != "")
    {
        of.close();
        of.open(pswFileName, std::ios::out | std::ios::binary);
    }
    of.write((char*)rawKeyBuf.data(), rawKeyBuf.size());
    if (cipherType == "QTag")
    {
        uint32_t sizeNet = htonl((uint32_t)rawKeyBuf.size());
        of.write((char*)&sizeNet, 4);
        of.write("QTag", 4);
    }
    else
    {
        uint32_t size = rawKeyBuf.size();
        of.write((char*)&size, 4);
    }
    encSuccess++;
}

void QmcEncode::EncodeCache()
{
    std::vector<uint8_t> v;
    v.resize(fileSizeG(f));
    f.seekg(0, std::ios::beg);
    if (f.fail())
    {
        encFailure++;
        return;
    }
    f.read((char*)v.data(), v.size());
    if (f.fail())
    {
        encFailure++;
        return;
    }
    for (size_t i = 0; i < v.size(); i++) {
        auto remainder = v[i] % 4;
        if (remainder == 0)
        {
            v[i] = v[i] / 4;
            if (v[i] > 0x3f)
            {
                encFailure++;
                return;
            }
        }
        else if (remainder == 1)
        {
            v[i] = (v[i] - 1) / 4 + 0x40;
            if (v[i] > 0x7f)
            {
                encFailure++;
                return;
            }
        }
        else if (remainder == 2)
        {
            v[i] = (v[i] - 2) / 4 + 0x80;
            if (v[i] > 0xbf)
            {
                encFailure++;
                return;
            }
        }
        else
        {
            v[i] = (v[i] - 3) / 4 + 0xc0;
            if (v[i] <= 0xbf)
            {
                encFailure++;
                return;
            }
        }
        v[i] ^= 0xf4;
    }
    std::string fn = fileName.substr(0, fileName.find_last_of(".")) + ".cache";
    std::cout << "Output:\n" << fn << std::endl;
    std::ofstream of(fn, std::ios::out | std::ios::binary | std::ios::trunc);
    of.write((char*)v.data(), v.size());
    encSuccess++;
}

void QmcEncode::EncodeTm()
{
    srand(time(0));
    std::vector<uint8_t> v;
    v.resize(fileSizeG(f));
    f.seekg(0, std::ios::beg);
    if (f.fail())
    {
        encFailure++;
        return;
    }
    f.read((char*)v.data(), v.size());
    if (f.fail())
    {
        encFailure++;
        return;
    }
    for (size_t cur = 0; cur < 8; cur++) {
        v[cur] = rand();
    }
    std::string fn = fileName.substr(0, fileName.find_last_of(".")) + ".tm" + ext;
    std::cout << "Output:\n" << fn << std::endl;
    std::ofstream of(fn, std::ios::out | std::ios::binary | std::ios::trunc);
    of.write((char*)v.data(), v.size());
    encSuccess++;
}

void QmcEncode::Encode()
{
    if (cipherType == "Map" || cipherType == "RC4" || cipherType == "QTag")
    {
        EncodeMapRC4();
    }
    else if (cipherType == "Static")
    {
        EncodeStatic();
    }
    else if (cipherType == "cache")
    {
        EncodeCache();
    }
    else if (cipherType == "ios")
    {
        EncodeTm();
    }
    else {
        std::cout << "File is invalid or encryption type is not supported." << std::endl;
        std::cin.get();
    }
}
