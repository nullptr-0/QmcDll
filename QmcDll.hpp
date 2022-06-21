#pragma comment(lib,"QmcDll.lib")

void __declspec(dllexport) qmcEncS(const char* fn, const char* type);

void __declspec(dllexport) qmcDecS(const char* fn);

void __declspec(dllexport) qmcEncD(const char* fn, const char* pswFn, const char* type);

void __declspec(dllexport) qmcDecD(const char* fn, const char* pswFn);
