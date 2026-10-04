// ============================================================
// IMPLEMENT THE WINDOWS DIRECTINPUT CONTRACT AND EDEN MOD LOADING
// Keep the six system exports and remove unrelated multi-game proxy behavior.
// ============================================================
#define DIRECTINPUT_VERSION 0x0800
#include <windows.h>
#include <dinput.h>
#include "loader_security.h"
#ifdef FF8_EARLY_STARTUP
#include "ff8_bootstrap_gate.h"
#endif

namespace eden_dinput8 {

// ============================================================
// TRACK THE PROXY MODULE AND PUBLISH ORIGINAL EXPORTS ONCE
// No other library is loaded and no host memory is patched in DllMain.
// ============================================================
HMODULE proxy_module = nullptr;
static HMODULE system_module = nullptr;
static INIT_ONCE system_initialization = INIT_ONCE_STATIC_INIT;
static volatile LONG plugin_state = 0;
static FARPROC system_functions[6] = {};
static const char* const export_names[6] = {
    "DirectInput8Create", "DllCanUnloadNow", "DllGetClassObject",
    "DllRegisterServer", "DllUnregisterServer", "GetdfDIJoystick"
};

// ============================================================
// LOAD THE SAME-ARCHITECTURE DIRECTINPUT DLL FROM THE SYSTEM DIRECTORY
// Resolve the public interface before making it available to any caller.
// ============================================================
BOOL CALLBACK InitializeSystemLibrary(PINIT_ONCE, PVOID, PVOID*) {
    wchar_t directory[32768] = {};
    const UINT length = GetSystemDirectoryW(directory, _countof(directory));
    if (length == 0 || length >= _countof(directory)) return FALSE;
    const std::wstring filename = std::wstring(directory, length) + L"\\dinput8.dll";
    HMODULE original = LoadLibraryExW(filename.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!original) return FALSE;
    if (original == proxy_module) { FreeLibrary(original); SetLastError(ERROR_DLL_INIT_FAILED); return FALSE; }
    FARPROC functions[6] = {};
    for (size_t index = 0; index < _countof(functions); ++index) {
        functions[index] = GetProcAddress(original, export_names[index]);
        if (!functions[index]) { FreeLibrary(original); SetLastError(ERROR_PROC_NOT_FOUND); return FALSE; }
    }
    for (size_t index = 0; index < _countof(functions); ++index) system_functions[index] = functions[index];
    system_module = original;
    return TRUE;
}

// ============================================================
// LOAD CONFIGURED MODS IN ORDER FROM ABSOLUTE UNICODE PATHS
// Preserve plugins.cfg precedence and avoid process-wide directory changes.
// ============================================================
void LoadConfiguredPlugins() {
    const std::wstring directory = loader_security::Directory(loader_security::ModulePath(proxy_module));
    if (directory.empty()) return;
    FILE* configuration = _wfopen((directory + L"\\plugins.cfg").c_str(), L"rb");
    if (!configuration) configuration = _wfopen((directory + L"\\dlls.cfg").c_str(), L"rb");
    if (!configuration) return;
    std::string line;
    try {
        while (true) {
            const auto result = loader_security::ReadLine(configuration, line);
            if (result == loader_security::LineResult::End) break;
            if (result == loader_security::LineResult::Oversized) continue;
            const std::wstring filename = loader_security::AbsolutePath(directory, loader_security::DecodePath(line));
            if (filename.empty()) continue;
            const DWORD attributes = GetFileAttributesW(filename.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!LoadLibraryExW(filename.c_str(), nullptr,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS))
                OutputDebugStringW(L"Eden DirectInput loader: configured DLL could not be loaded.\n");
        }
    } catch (...) {
        OutputDebugStringW(L"Eden DirectInput loader: configuration processing failed.\n");
    }
    std::fclose(configuration);
}

// ============================================================
// INITIALIZE ON THE FIRST FORWARDED API AND GUARD MOD REENTRANCY
// Reentrant calls can use the original system API while mods are initializing.
// ============================================================
bool InitializeProxy() {
    try {
        if (!InitOnceExecuteOnce(&system_initialization, InitializeSystemLibrary, nullptr, nullptr)) return false;
        bool loading_allowed = true;
#ifdef FF8_EARLY_STARTUP
        loading_allowed = ff8_bootstrap::ModLoadingAllowed();
#endif
        if (loading_allowed && InterlockedCompareExchange(&plugin_state, 1, 0) == 0) {
            try { LoadConfiguredPlugins(); }
            catch (...) { OutputDebugStringW(L"Eden DirectInput loader: plugin initialization failed.\n"); }
            InterlockedExchange(&plugin_state, 2);
        }
        return true;
    } catch (...) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
}

HRESULT InitializationError() {
    const DWORD error = GetLastError();
    return HRESULT_FROM_WIN32(error ? error : ERROR_DLL_INIT_FAILED);
}

} // namespace eden_dinput8

// ============================================================
// FORWARD THE SIX SYSTEM EXPORTS WITH THEIR ORIGINAL STDCALL ABI
// Registry-related exports only delegate when explicitly invoked by a caller.
// ============================================================
extern "C" HRESULT WINAPI EdenDirectInput8Create(HINSTANCE instance, DWORD version, REFIID interface_id, LPVOID* output, LPUNKNOWN outer) {
    if (!eden_dinput8::InitializeProxy()) { if (output) *output = nullptr; return eden_dinput8::InitializationError(); }
    using Function = HRESULT (WINAPI*)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
    return reinterpret_cast<Function>(eden_dinput8::system_functions[0])(instance, version, interface_id, output, outer);
}
extern "C" HRESULT WINAPI EdenDllCanUnloadNow() {
    if (!eden_dinput8::InitializeProxy()) return S_FALSE;
    return reinterpret_cast<HRESULT (WINAPI*)()>(eden_dinput8::system_functions[1])();
}
extern "C" HRESULT WINAPI EdenDllGetClassObject(REFCLSID class_id, REFIID interface_id, LPVOID* output) {
    if (!eden_dinput8::InitializeProxy()) { if (output) *output = nullptr; return eden_dinput8::InitializationError(); }
    using Function = HRESULT (WINAPI*)(REFCLSID, REFIID, LPVOID*);
    return reinterpret_cast<Function>(eden_dinput8::system_functions[2])(class_id, interface_id, output);
}
extern "C" HRESULT WINAPI EdenDllRegisterServer() {
    if (!eden_dinput8::InitializeProxy()) return eden_dinput8::InitializationError();
    return reinterpret_cast<HRESULT (WINAPI*)()>(eden_dinput8::system_functions[3])();
}
extern "C" HRESULT WINAPI EdenDllUnregisterServer() {
    if (!eden_dinput8::InitializeProxy()) return eden_dinput8::InitializationError();
    return reinterpret_cast<HRESULT (WINAPI*)()>(eden_dinput8::system_functions[4])();
}
extern "C" const DIDATAFORMAT* WINAPI EdenGetdfDIJoystick() {
    if (!eden_dinput8::InitializeProxy()) return nullptr;
    return reinterpret_cast<const DIDATAFORMAT* (WINAPI*)()>(eden_dinput8::system_functions[5])();
}

// ============================================================
// STORE THE MODULE HANDLE WITHOUT STARTUP HOOKS OR THREAD CREATION
// Normal DirectInput calls trigger all further initialization outside this entrypoint.
// ============================================================
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        eden_dinput8::proxy_module = module;
#ifdef FF8_EARLY_STARTUP
        ff8_bootstrap::Install(GetModuleHandleW(nullptr), eden_dinput8::InitializeProxy);
#endif
    }
    return TRUE;
}
