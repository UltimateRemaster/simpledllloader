#include "dllmain.h"
#include "loader_security.h"

// ============================================================
// RETAIN THE LEGACY PROXY GLOBALS AND TRACK SAFE INITIALIZATION
// Existing forwarding stubs require these names and module tables.
// ============================================================
HMODULE hm;
bool bLoadedPluginsYet;
volatile LONG bOriginalLibraryLoaded;
char iniPath[MAX_PATH];
static INIT_ONCE original_library_once = INIT_ONCE_STATIC_INIT;
static volatile LONG plugin_initialization_state = 0;
static volatile LONG kernel_hooks_ready = 0;

// ============================================================
// RECORD EVERY INSTALLED KERNEL HOOK FOR CONDITIONAL RESTORATION
// Multiple slots for the same API must all be restored without overwriting another mod.
// ============================================================
struct ImportPatch { size_t* slot; size_t original; size_t replacement; };
static ImportPatch import_patches[512] = {};
static size_t import_patch_count = 0;

enum Kernel32ExportsNames
{
    eGetStartupInfoA,
    eGetStartupInfoW,
    eGetModuleHandleA,
    eGetModuleHandleW,
    eGetProcAddress,
    eGetShortPathNameA,
    eFindNextFileA,
    eFindNextFileW,
    eLoadLibraryA,
    eLoadLibraryW,
    eFreeLibrary,

    Kernel32ExportsNamesCount
};

enum Kernel32ExportsData
{
    IATPtr,
    ProcAddress,

    Kernel32ExportsDataCount
};

size_t Kernel32Data[Kernel32ExportsNamesCount][Kernel32ExportsDataCount];

// ============================================================
// INITIALIZE THE ORIGINAL SYSTEM PROXY ONCE WITH AN EXPLICIT PATH
// This callback is reached from a forwarded call, outside DllMain in dinput8 mode.
// ============================================================
BOOL CALLBACK InitializeOriginalLibrary(PINIT_ONCE, PVOID, PVOID*)
{
    const std::wstring module_path = loader_security::ModulePath(hm);
    const size_t separator = module_path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) return FALSE;
    const std::wstring filename = module_path.substr(separator + 1);
    char name_buffer[128] = {};
    if (!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, filename.c_str(), -1,
        name_buffer + 1, sizeof(name_buffer) - 1, nullptr, nullptr)) return FALSE;
    const char* SelfName = name_buffer;
    std::vector<wchar_t> system_directory(32768);
    const UINT system_length = GetSystemDirectoryW(system_directory.data(), static_cast<UINT>(system_directory.size()));
    if (system_length == 0 || system_length >= system_directory.size()) return FALSE;
    const std::wstring original_path = std::wstring(system_directory.data(), system_length) + L"\\" + filename;
    const bool local_vorbis = _stricmp(SelfName + 1, "vorbisFile.dll") == 0;
    const bool local_xlive = _stricmp(SelfName + 1, "xlive.dll") == 0;
    HMODULE original_module = nullptr;
    if (!local_vorbis && !local_xlive) {
        original_module = LoadLibraryExW(original_path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!original_module || original_module == hm) return FALSE;
    }

#if !X64
	if(_stricmp(SelfName + 1, "vorbisFile.dll") == 0){
		const std::wstring vorbis_path = loader_security::Directory(module_path) + L"\\vorbisFileHooked.dll";
		HMODULE module = LoadLibraryExW(vorbis_path.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
		if(module == 0){
			MessageBox(0, "Could not load library vorbisFileHooked.dll", "DLL Loader", MB_ICONERROR);
			ExitProcess(0);
		}
		vorbisfile.LoadOriginalLibrary(module);

		// Unprotect the module NOW (CLEO 4.1.1.30f crash fix)
		auto hExecutableInstance = (size_t)GetModuleHandle(NULL);
		IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(hExecutableInstance + ((IMAGE_DOS_HEADER*)hExecutableInstance)->e_lfanew);
		SIZE_T size = ntHeader->OptionalHeader.SizeOfImage;
		DWORD oldProtect;
		VirtualProtect((VOID*)hExecutableInstance, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	}else if (_stricmp(SelfName + 1, "dsound.dll") == 0)
		dsound.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "dinput8.dll") == 0)
		dinput8.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "ddraw.dll") == 0)
		ddraw.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "d3d8.dll") == 0)
		d3d8.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "d3d9.dll") == 0)
		d3d9.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "d3d11.dll") == 0)
		d3d11.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "winmmbase.dll") == 0)
		winmmbase.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "msacm32.dll") == 0)
		msacm32.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "dinput.dll") == 0)
		dinput.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "msvfw32.dll") == 0)
		msvfw32.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "xlive.dll") == 0){
		// Unprotect image - make .text and .rdata section writeable
		// get load address of the exe
		size_t dwLoadOffset = (size_t)GetModuleHandle(NULL);
		BYTE * pImageBase = reinterpret_cast<BYTE *>(dwLoadOffset);
		PIMAGE_DOS_HEADER   pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dwLoadOffset);
		PIMAGE_NT_HEADERS   pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(pImageBase + pDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);

		for (int iSection = 0; iSection < pNtHeader->FileHeader.NumberOfSections; ++iSection, ++pSection) {
		    char * pszSectionName = reinterpret_cast<char *>(pSection->Name);
		    if (!strcmp(pszSectionName, ".text") || !strcmp(pszSectionName, ".rdata")) {
		        DWORD dwPhysSize = (pSection->Misc.VirtualSize + 4095) & ~4095;
		        DWORD	oldProtect;
		        DWORD   newProtect = (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
		        if (!VirtualProtect(reinterpret_cast <VOID *>(dwLoadOffset + pSection->VirtualAddress), dwPhysSize, newProtect, &oldProtect)) {
		            ExitProcess(0);
		        }
		    }
		}
	}else{
		MessageBox(0, "This library isn't supported. Try to rename it to d3d8.dll, d3d9.dll, d3d11.dll, winmmbase.dll, msacm32.dll, dinput.dll, dinput8.dll, dsound.dll, vorbisFile.dll, msvfw32.dll, xlive.dll or ddraw.dll.", "DLL Loader", MB_ICONERROR);
		ExitProcess(0);
	}
#else
	if (_stricmp(SelfName + 1, "dsound.dll") == 0)
		dsound.LoadOriginalLibrary(original_module);
	else if (_stricmp(SelfName + 1, "dinput8.dll") == 0)
		dinput8.LoadOriginalLibrary(original_module);
	else{
		MessageBox(0, "This library isn't supported. Try to rename it to dsound.dll or dinput8.dll.", "DLL Loader", MB_ICONERROR);
		ExitProcess(0);
	}
#endif
    if (_stricmp(SelfName + 1, "dinput8.dll") == 0 && !dinput8.DirectInput8Create) return FALSE;
    InterlockedExchange(&bOriginalLibraryLoaded, 1);
    return TRUE;
}

// ============================================================
// REQUIRE A VALID ORIGINAL LIBRARY BEFORE ANY FORWARDING STUB
// InitOnce publishes the completed function table to concurrent callers.
// ============================================================
void LoadOriginalLibrary() {
    if (!InitOnceExecuteOnce(&original_library_once, InitializeOriginalLibrary, nullptr, nullptr)) {
        OutputDebugStringW(L"Simple DLL Loader: original system library could not be loaded.\n");
        ExitProcess(ERROR_DLL_INIT_FAILED);
    }
}

#if !X64
void Direct3D8DisableMaximizedWindowedModeShim()
{
    auto nDirect3D8DisableMaximizedWindowedModeShim = GetPrivateProfileInt("globalsets", "Direct3D8DisableMaximizedWindowedModeShim", FALSE, iniPath);
    if (nDirect3D8DisableMaximizedWindowedModeShim)
    {
        HMODULE pd3d8 = NULL;
        if (d3d8.dll)
        {
            pd3d8 = d3d8.dll;
        }
        else
        {
            pd3d8 = LoadLibrary("d3d8.dll");
            if (!pd3d8)
            {
                TCHAR szSystemPath[MAX_PATH];
                SHGetFolderPath(NULL, CSIDL_SYSTEM, NULL, 0, szSystemPath);
                strcat_s(szSystemPath, "\\d3d8.dll");
                pd3d8 = LoadLibrary(szSystemPath);
            }
        }

        if (pd3d8)
        {
            auto addr = (uintptr_t)GetProcAddress(pd3d8, "Direct3D8EnableMaximizedWindowedModeShim");
            if (addr)
            {
                DWORD Protect;
                VirtualProtect((LPVOID)(addr + 6), 4, PAGE_EXECUTE_READWRITE, &Protect);
                *(uint32_t*)(addr + 6) = 0;
                *(uint32_t*)(*(uint32_t*)(addr + 2)) = 0;
                VirtualProtect((LPVOID)(addr + 6), 4, Protect, &Protect);
            }
        }
    }
}
#endif

void LoadPlugins()
{
    // ============================================================
    // OPEN THE EXISTING CONFIG PRECEDENCE WITHOUT CHANGING CWD
    // UTF8/ANSI entries are resolved against the actual loader directory.
    // ============================================================
    const std::wstring directory = loader_security::Directory(loader_security::ModulePath(hm));
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
            const std::wstring path = loader_security::AbsolutePath(directory, loader_security::DecodePath(line));
            if (path.empty()) continue;
            const DWORD attributes = GetFileAttributesW(path.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (!LoadLibraryExW(path.c_str(), nullptr,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS))
                OutputDebugStringW(L"Simple DLL Loader: a configured plugin could not be loaded.\n");
        }
    } catch (...) {
        OutputDebugStringW(L"Simple DLL Loader: configuration processing failed.\n");
    }
    std::fclose(configuration);
}

void LoadEverything()
{
    // ============================================================
    // PUBLISH ORIGINAL EXPORTS BEFORE REENTRANT PLUGIN INITIALIZATION
    // Do not wait on another plugin-loading thread while a DLL may hold loader lock.
    // ============================================================
    if (!InterlockedCompareExchange(&bOriginalLibraryLoaded, 0, 0)) LoadOriginalLibrary();
    if (InterlockedCompareExchange(&plugin_initialization_state, 1, 0) == 0)
    {
#if !X64
        Direct3D8DisableMaximizedWindowedModeShim();
#endif
        LoadPlugins();
        bLoadedPluginsYet = true;
        InterlockedExchange(&plugin_initialization_state, 2);
    }
}

void LoadPluginsAndRestoreIAT()
{
    if (!InterlockedCompareExchange(&kernel_hooks_ready, 0, 0)) return;
    LoadEverything();
    if (InterlockedCompareExchange(&plugin_initialization_state, 0, 0) != 2) return;
    // ============================================================
    // RESTORE EVERY OWNED SLOT AND PRESERVE OTHER MODS' HOOKS
    // Restore the previous page protection immediately after each slot write.
    // ============================================================
    for (size_t index = 0; index < import_patch_count; ++index)
    {
        const auto& patch = import_patches[index];
        loader_security::ImportWrite protection(patch.slot);
        if (protection.Ready()) InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(patch.slot), reinterpret_cast<PVOID>(patch.original),
            reinterpret_cast<PVOID>(patch.replacement));
    }
}

void WINAPI CustomGetStartupInfoA(LPSTARTUPINFOA lpStartupInfo)
{
    LoadPluginsAndRestoreIAT();
    return GetStartupInfoA(lpStartupInfo);
}

void WINAPI CustomGetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)
{
    LoadPluginsAndRestoreIAT();
    return GetStartupInfoW(lpStartupInfo);
}

HMODULE WINAPI CustomGetModuleHandleA(LPCSTR lpModuleName)
{
    LoadPluginsAndRestoreIAT();
    return GetModuleHandleA(lpModuleName);
}

HMODULE WINAPI CustomGetModuleHandleW(LPCWSTR lpModuleName)
{
    LoadPluginsAndRestoreIAT();
    return GetModuleHandleW(lpModuleName);
}

FARPROC WINAPI CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    LoadPluginsAndRestoreIAT();
    return GetProcAddress(hModule, lpProcName);
}

DWORD WINAPI CustomGetShortPathNameA(LPCSTR lpszLongPath, LPSTR lpszShortPath, DWORD cchBuffer)
{
    LoadPluginsAndRestoreIAT();
    return GetShortPathNameA(lpszLongPath, lpszShortPath, cchBuffer);
}

BOOL WINAPI CustomFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
    LoadPluginsAndRestoreIAT();
    return FindNextFileA(hFindFile, lpFindFileData);
}

BOOL WINAPI CustomFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
    LoadPluginsAndRestoreIAT();
    return FindNextFileW(hFindFile, lpFindFileData);
}

HMODULE WINAPI CustomLoadLibraryA(LPCSTR lpLibFileName)
{
    if (InterlockedCompareExchange(&kernel_hooks_ready, 0, 0) && !InterlockedCompareExchange(&bOriginalLibraryLoaded, 0, 0))
        LoadOriginalLibrary();

    return LoadLibraryA(lpLibFileName);
}

HMODULE WINAPI CustomLoadLibraryW(LPCWSTR lpLibFileName)
{
    if (InterlockedCompareExchange(&kernel_hooks_ready, 0, 0) && !InterlockedCompareExchange(&bOriginalLibraryLoaded, 0, 0))
        LoadOriginalLibrary();

    return LoadLibraryW(lpLibFileName);
}

BOOL WINAPI CustomFreeLibrary(HMODULE hLibModule)
{
    if (hLibModule != hm)
        return FreeLibrary(hLibModule);
    else
        return !NULL;
}

void PatchHostImports(HMODULE host, const char* SelfName)
{
    // ============================================================
    // VALIDATE THE MAPPED HOST IMAGE AND BOUND EVERY IMPORT WALK
    // Invalid or absent imports fall back to deferred DirectInput forwarding.
    // ============================================================
    loader_security::ImageView image;
    IMAGE_IMPORT_DESCRIPTOR* pImports = nullptr;
    size_t nNumImports = 0;
    if (!SelfName || !loader_security::DescribeImage(host, image) ||
        !loader_security::ImportDirectory(image, pImports, nNumImports)) return;
    const size_t hExecutableInstance = reinterpret_cast<size_t>(image.base);

    Kernel32Data[eGetStartupInfoA]  [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "GetStartupInfoA");
    Kernel32Data[eGetStartupInfoW]  [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "GetStartupInfoW");
    Kernel32Data[eGetModuleHandleA] [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "GetModuleHandleA");
    Kernel32Data[eGetModuleHandleW] [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "GetModuleHandleW");
    Kernel32Data[eGetProcAddress]   [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "GetProcAddress");
    Kernel32Data[eGetShortPathNameA][ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "GetShortPathNameA");
    Kernel32Data[eFindNextFileA]    [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "FindNextFileA");
    Kernel32Data[eFindNextFileW]    [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "FindNextFileW");
    Kernel32Data[eLoadLibraryA]     [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "LoadLibraryA");
    Kernel32Data[eLoadLibraryW]     [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "LoadLibraryW");
    Kernel32Data[eFreeLibrary]      [ProcAddress] = (size_t)GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "FreeLibrary");

    auto PatchIAT = [&image](size_t start, size_t end, size_t exe_end)
    {
        if (!end || end > exe_end) end = exe_end;
        if (start < reinterpret_cast<size_t>(image.base) || start > end) return;
        for (auto i = start; i < end && sizeof(size_t) <= end - i; i += sizeof(size_t))
        {
            auto ptr = *(size_t*)i;
            if (!ptr) break;
            bool relevant = false;
            for (size_t function_index = 0; function_index < Kernel32ExportsNamesCount; ++function_index)
                relevant = relevant || (ptr == Kernel32Data[function_index][ProcAddress]);
            if (!relevant || import_patch_count == _countof(import_patches)) continue;
            loader_security::ImportWrite protection(reinterpret_cast<void*>(i));
            if (!protection.Ready()) continue;
            size_t replacement = ptr;

            if (ptr == Kernel32Data[eGetStartupInfoA][ProcAddress])
            {
                Kernel32Data[eGetStartupInfoA][IATPtr] = i;
                replacement = (size_t)CustomGetStartupInfoA;
            }
            else if (ptr == Kernel32Data[eGetStartupInfoW][ProcAddress])
            {
                Kernel32Data[eGetStartupInfoW][IATPtr] = i;
                replacement = (size_t)CustomGetStartupInfoW;
            }
            else if (ptr == Kernel32Data[eGetModuleHandleA][ProcAddress])
            {
                Kernel32Data[eGetModuleHandleA][IATPtr] = i;
                replacement = (size_t)CustomGetModuleHandleA;
            }
            else if (ptr == Kernel32Data[eGetModuleHandleW][ProcAddress])
            {
                Kernel32Data[eGetModuleHandleW][IATPtr] = i;
                replacement = (size_t)CustomGetModuleHandleW;
            }
            else if (ptr == Kernel32Data[eGetProcAddress][ProcAddress])
            {
                Kernel32Data[eGetProcAddress][IATPtr] = i;
                replacement = (size_t)CustomGetProcAddress;
            }
            else if (ptr == Kernel32Data[eGetShortPathNameA][ProcAddress])
            {
                Kernel32Data[eGetShortPathNameA][IATPtr] = i;
                replacement = (size_t)CustomGetShortPathNameA;
            }
            else if (ptr == Kernel32Data[eFindNextFileA][ProcAddress])
            {
                Kernel32Data[eFindNextFileA][IATPtr] = i;
                replacement = (size_t)CustomFindNextFileA;
            }
            else if (ptr == Kernel32Data[eFindNextFileW][ProcAddress])
            {
                Kernel32Data[eFindNextFileW][IATPtr] = i;
                replacement = (size_t)CustomFindNextFileW;
            }
            else if (ptr == Kernel32Data[eLoadLibraryA][ProcAddress])
            {
                Kernel32Data[eLoadLibraryA][IATPtr] = i;
                replacement = (size_t)CustomLoadLibraryA;
            }
            else if (ptr == Kernel32Data[eLoadLibraryW][ProcAddress])
            {
                Kernel32Data[eLoadLibraryW][IATPtr] = i;
                replacement = (size_t)CustomLoadLibraryW;
            }
            else if (ptr == Kernel32Data[eFreeLibrary][ProcAddress])
            {
                Kernel32Data[eFreeLibrary][IATPtr] = i;
                replacement = (size_t)CustomFreeLibrary;
            }

            if (replacement != ptr && reinterpret_cast<size_t>(InterlockedCompareExchangePointer(
                reinterpret_cast<PVOID volatile*>(i), reinterpret_cast<PVOID>(replacement), reinterpret_cast<PVOID>(ptr))) == ptr)
                import_patches[import_patch_count++] = {reinterpret_cast<size_t*>(i), ptr, replacement};
        }
    };

    const size_t hExecutableInstance_end = hExecutableInstance + image.length;
    
    // Find kernel32.dll
    for (size_t i = 0; i < nNumImports; i++)
    {
        if (!(pImports + i)->Name) break;
        if ((pImports + i)->FirstThunk && (pImports + i)->FirstThunk % sizeof(size_t) == 0 && image.StringAt((pImports + i)->Name) &&
            image.Contains((pImports + i)->FirstThunk, sizeof(IMAGE_THUNK_DATA)))
        {
            if (!_stricmp((const char*)(hExecutableInstance + (pImports + i)->Name), "KERNEL32.DLL"))
                PatchIAT(hExecutableInstance + (pImports + i)->FirstThunk, 0, hExecutableInstance_end);

            //Checking for ordinals
            if (!_stricmp((const char*)(hExecutableInstance + (pImports + i)->Name), SelfName))
            {
                if (!(pImports + i)->OriginalFirstThunk ||
                    !image.Contains((pImports + i)->OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA))) continue;
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(hExecutableInstance + (pImports + i)->OriginalFirstThunk);
                size_t j = 0;
                while (image.Contains((pImports + i)->OriginalFirstThunk + j * sizeof(IMAGE_THUNK_DATA), sizeof(IMAGE_THUNK_DATA)) &&
                    image.Contains((pImports + i)->FirstThunk + j * sizeof(size_t), sizeof(size_t)) && thunk->u1.Function)
                {
                    if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    {
                        void** p = (void**)(hExecutableInstance + (pImports + i)->FirstThunk);
                        loader_security::ImportWrite protection(&p[j]);
                        if (!protection.Ready()) { ++thunk; ++j; continue; }
                        if (!_stricmp(SelfName, "DSOUND.DLL"))
                        {
                            const enum edsound
                            {
                                DirectSoundCaptureCreate = 6,
                                DirectSoundCaptureCreate8 = 12,
                                DirectSoundCaptureEnumerateA = 7,
                                DirectSoundCaptureEnumerateW = 8,
                                DirectSoundCreate = 1,
                                DirectSoundCreate8 = 11,
                                DirectSoundEnumerateA = 2,
                                DirectSoundEnumerateW = 3,
                                DirectSoundFullDuplexCreate = 10,
                                GetDeviceID = 9
                            };

                            switch (IMAGE_ORDINAL(thunk->u1.Ordinal))
                            {
                            case edsound::DirectSoundCaptureCreate:
                                p[j] = _DirectSoundCaptureCreate;
                                break;
                            case edsound::DirectSoundCaptureCreate8:
                                p[j] = _DirectSoundCaptureCreate8;
                                break;
                            case edsound::DirectSoundCaptureEnumerateA:
                                p[j] = _DirectSoundCaptureEnumerateA;
                                break;
                            case edsound::DirectSoundCaptureEnumerateW:
                                p[j] = _DirectSoundCaptureEnumerateW;
                                break;
                            case edsound::DirectSoundCreate:
                                p[j] = _DirectSoundCreate;
                                break;
                            case edsound::DirectSoundCreate8:
                                p[j] = _DirectSoundCreate8;
                                break;
                            case edsound::DirectSoundEnumerateA:
                                p[j] = _DirectSoundEnumerateA;
                                break;
                            case edsound::DirectSoundEnumerateW:
                                p[j] = _DirectSoundEnumerateW;
                                break;
                            case edsound::DirectSoundFullDuplexCreate:
                                p[j] = _DirectSoundFullDuplexCreate;
                                break;
                            case edsound::GetDeviceID:
                                p[j] = _GetDeviceID;
                                break;
                            default:
                                break;
                            }
                        }
                        else if (!_stricmp(SelfName, "DINPUT8.DLL"))
                        {
                            if ((IMAGE_ORDINAL(thunk->u1.Ordinal)) == 1)
                                p[j] = _DirectInput8Create;
                        }
                    }
                    ++thunk;
                    ++j;
                }
            }
        }
    }
}

// ============================================================
// APPLY HOST HOOKS USING THE ACTUAL PROXY BASENAME
// The descriptor patcher is separately testable with an isolated PE fixture.
// ============================================================
void HookKernel32IAT() {
    const std::wstring module_path = loader_security::ModulePath(hm);
    const size_t separator = module_path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) return;
    char filename[128] = {};
    if (!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, module_path.c_str() + separator + 1,
        -1, filename, _countof(filename), nullptr, nullptr)) return;
    PatchHostImports(GetModuleHandleW(nullptr), filename);
}

void Init()
{
    // ============================================================
    // READ BOOTSTRAP SETTINGS BY ABSOLUTE UNICODE PATH
    // DirectInput exports provide safe lazy initialization when hooks are disabled.
    // ============================================================
    const std::wstring module_path = loader_security::ModulePath(hm);
    const std::wstring configuration_path = loader_security::Directory(module_path) + L"\\dllloader.ini";
    WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, configuration_path.c_str(), -1,
        iniPath, _countof(iniPath), nullptr, nullptr);
    auto nForceEPHook = GetPrivateProfileIntW(L"globalsets", L"forceentrypointhook", TRUE, configuration_path.c_str());

    if (GetModuleHandle(NULL) && nForceEPHook != FALSE)
    {
        HookKernel32IAT();
    }
    else
    {
        const size_t separator = module_path.find_last_of(L"\\/");
        if (separator == std::wstring::npos || _wcsicmp(module_path.c_str() + separator + 1, L"dinput8.dll") != 0)
            LoadEverything();
    }
    InterlockedExchange(&kernel_hooks_ready, 1);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*lpReserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        hm = hModule;
        Init();
    }
    return TRUE;
}
