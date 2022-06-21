// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "qmc.hpp"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void __declspec(dllexport) qmcEncS(const char* fn, const char* type)
{
    QmcEncode e(fn, type);
    e.Encode();
}

void __declspec(dllexport) qmcDecS(const char* fn)
{
    QmcDecode e(fn);
    e.Decode();
}

void __declspec(dllexport) qmcEncD(const char* fn, const char* pswFn, const char* type)
{
    QmcEncode e(fn, pswFn, type);
    e.Encode();
}

void __declspec(dllexport) qmcDecD(const char* fn, const char* pswFn)
{
    QmcDecode e(fn, pswFn);
    e.Decode();
}
