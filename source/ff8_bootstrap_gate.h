// ============================================================
// LOAD MODS BEFORE THE BOOTSTRAP ENTERS THE FFVIII ENGINE
// Temporarily intercept only GetProcAddress in the known FFVIII executable.
// ============================================================
#pragma once
#include "loader_security.h"

namespace ff8_bootstrap {

// ============================================================
// KEEP A BOUNDED STARTUP HOOK AND THE ORIGINAL LOOKUP DELEGATE
// All recorded slots are restored before invoking any mod initialization.
// ============================================================
using LookupFunction = FARPROC (WINAPI*)(HMODULE, LPCSTR);
using StartupCallback = bool (*)();
struct LookupSlot { PVOID volatile* address; PVOID previous; };
static LookupSlot lookup_slots[16] = {};
static size_t lookup_slot_count = 0;
static LookupFunction previous_lookup = nullptr;
static StartupCallback startup_callback = nullptr;
static volatile LONG entry_triggered = 0;
static bool startup_required = false;

inline bool IsEngine(HMODULE module) {
    const std::wstring path = loader_security::ModulePath(module);
    const size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) return false;
    const wchar_t* filename = path.c_str() + separator + 1;
    return _wcsicmp(filename, L"FFVIII_EFIGS.dll") == 0 || _wcsicmp(filename, L"FFVIII_JP.dll") == 0;
}

// ============================================================
// RECOGNIZE THE ENGINE ENTRY BY ITS RESOLVED RUNGAME ADDRESS
// This also covers a caller using the export ordinal instead of the name.
// ============================================================
inline FARPROC WINAPI Lookup(HMODULE module, LPCSTR name) {
    const LookupFunction delegate = previous_lookup ? previous_lookup : GetProcAddress;
    FARPROC result = delegate(module, name);
    if (result && IsEngine(module) && result == delegate(module, "runGame") &&
        InterlockedCompareExchange(&entry_triggered, 1, 0) == 0) {
        for (size_t index = 0; index < lookup_slot_count; ++index) {
            const auto& slot = lookup_slots[index];
            loader_security::ImportWrite protection(const_cast<PVOID*>(slot.address));
            if (protection.Ready()) InterlockedCompareExchangePointer(slot.address, slot.previous, reinterpret_cast<PVOID>(Lookup));
        }
        if (startup_callback && !startup_callback()) OutputDebugStringW(L"Eden loader: early mod initialization failed.\n");
    }
    return result;
}

// ============================================================
// INSTALL ONLY NAMED GETPROCADDRESS SLOTS IN THE KNOWN BOOTSTRAP
// Other executables retain normal lazy initialization for isolated testing.
// ============================================================
inline void Install(HMODULE host, StartupCallback callback) {
    const std::wstring path = loader_security::ModulePath(host);
    const size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos || _wcsicmp(path.c_str() + separator + 1, L"FFVIII.exe") != 0) return;
    startup_required = true;
    startup_callback = callback;
    loader_security::ImageView image;
    IMAGE_IMPORT_DESCRIPTOR* descriptors = nullptr;
    size_t descriptor_count = 0;
    if (!loader_security::DescribeImage(host, image) || !loader_security::ImportDirectory(image, descriptors, descriptor_count)) return;
    for (size_t index = 0; index < descriptor_count && descriptors[index].Name; ++index) {
        const auto& descriptor = descriptors[index];
        if (!descriptor.OriginalFirstThunk || !descriptor.FirstThunk) continue;
        size_t slot_index = 0;
        while (image.Contains(descriptor.OriginalFirstThunk + slot_index * sizeof(IMAGE_THUNK_DATA), sizeof(IMAGE_THUNK_DATA)) &&
            image.Contains(descriptor.FirstThunk + slot_index * sizeof(size_t), sizeof(size_t))) {
            const auto* name = reinterpret_cast<IMAGE_THUNK_DATA*>(image.base + descriptor.OriginalFirstThunk) + slot_index;
            if (!name->u1.AddressOfData) break;
            if (!(name->u1.Ordinal & IMAGE_ORDINAL_FLAG) && image.Contains(name->u1.AddressOfData, sizeof(WORD) + 1) &&
                image.StringAt(name->u1.AddressOfData + sizeof(WORD)) &&
                std::strcmp(reinterpret_cast<char*>(image.base + name->u1.AddressOfData + sizeof(WORD)), "GetProcAddress") == 0 &&
                lookup_slot_count < _countof(lookup_slots)) {
                auto* slot = reinterpret_cast<PVOID volatile*>(image.base + descriptor.FirstThunk) + slot_index;
                loader_security::ImportWrite protection(const_cast<PVOID*>(slot));
                if (protection.Ready()) {
                    PVOID original = *slot;
                    if (original && original != reinterpret_cast<PVOID>(Lookup) &&
                        (!previous_lookup || original == reinterpret_cast<PVOID>(previous_lookup))) {
                        previous_lookup = reinterpret_cast<LookupFunction>(original);
                        lookup_slots[lookup_slot_count++] = {slot, original};
                        InterlockedCompareExchangePointer(slot, reinterpret_cast<PVOID>(Lookup), original);
                    }
                }
            }
            ++slot_index;
        }
    }
    if (!lookup_slot_count) OutputDebugStringW(L"Eden loader: startup lookup hook unavailable; late mod loading suppressed.\n");
}

inline bool ModLoadingAllowed() {
    return !startup_required || InterlockedCompareExchange(&entry_triggered, 0, 0) != 0;
}

} // namespace ff8_bootstrap
