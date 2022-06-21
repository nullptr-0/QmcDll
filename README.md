# QmcDll
Qmc Encryption & Decryption Dynamic Link Library

# How to use
```
Other operations
1: Place the QmcDll.lib in yout project directory
2: Add `#include "QmcDll.hpp"` to your source
Other operations
```

# Functions
Name | Usage | Params
------------ | ------------- | -------------
qmcEncS | Encrypt, Single(No seperated key file) | Param1 (const char* fn): Name of file to encrypt, Param2 (const char* type): Encryption type("Map"/"RC4"/"QTag"/"Static"/"cache"/"ios")
qmcDecS | Decrypt, Single(No seperated key file) | Param (const char* fn): Name of file to decrypt
qmcEncD | Encrypt, Dual(With seperated key file) | Param1 (const char* fn) & Param3 (const char* type): see qmcEncS, Param2 (const char* pswFn): Name of file to store the key
qmcDecD | Decrypt, Dual(With seperated key file) | Param1 (const char* fn): see qmcDecS, Param2 (const char* pswFn): Name of file that stores the key
