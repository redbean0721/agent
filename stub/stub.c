#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>

void stub() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    while (1) { Sleep(1000); }
}