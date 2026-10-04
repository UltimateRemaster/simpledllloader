// ============================================================
// PROVIDE BOUNDED PATH AND MEMORY HELPERS FOR THE EDEN CANDIDATE
// Keep configuration loading local without changing process-wide search paths.
// ============================================================
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cctype>
#include <cstring>

namespace loader_security {

// ============================================================
// RESOLVE MODULE LOCATIONS AND EXPLICIT ABSOLUTE FILE PATHS
// Preserve explicit external paths while rejecting ambiguous drive-relative names.
// ============================================================
inline std::wstring ModulePath(HMODULE module) {
    std::vector<wchar_t> buffer(512);
    while (buffer.size() <= 32768) {
        const DWORD length = GetModuleFileNameW(module, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) return {};
        if (length < buffer.size()) return std::wstring(buffer.data(), length);
        if (buffer.size() == 32768) break;
        buffer.resize(buffer.size() * 2);
    }
    return {};
}

inline std::wstring Directory(const std::wstring& filename) {
    const size_t separator = filename.find_last_of(L"\\/");
    return separator == std::wstring::npos ? std::wstring() : filename.substr(0, separator);
}

inline std::wstring AbsolutePath(const std::wstring& directory, const std::wstring& filename) {
    if (directory.empty() || filename.empty() || filename.find(L'\0') != std::wstring::npos) return {};
    const bool drive_path = filename.size() > 2 && filename[1] == L':' &&
        (filename[2] == L'\\' || filename[2] == L'/');
    const bool network_path = filename.size() > 1 && filename[0] == L'\\' && filename[1] == L'\\';
    if (!drive_path && !network_path &&
        (filename[0] == L'\\' || filename[0] == L'/' || filename.find(L':') != std::wstring::npos)) return {};
    const std::wstring combined = drive_path || network_path ? filename : directory + L"\\" + filename;
    const DWORD required = GetFullPathNameW(combined.c_str(), 0, nullptr, nullptr);
    if (required == 0 || required > 32768) return {};
    std::vector<wchar_t> buffer(required);
    const DWORD length = GetFullPathNameW(combined.c_str(), required, buffer.data(), nullptr);
    if (length == 0 || length >= required) return {};
    std::wstring absolute(buffer.data(), length);
    if (absolute.size() >= MAX_PATH && absolute.compare(0, 4, L"\\\\?\\") != 0)
        absolute = absolute.compare(0, 2, L"\\\\") == 0 ? L"\\\\?\\UNC\\" + absolute.substr(2) : L"\\\\?\\" + absolute;
    return absolute;
}

// ============================================================
// READ COMPLETE CONFIG LINES AND DECODE UTF8 OR LEGACY ANSI NAMES
// Consume oversized lines entirely instead of loading their individual fragments.
// ============================================================
enum class LineResult { End, Complete, Oversized };
inline LineResult ReadLine(FILE* configuration, std::string& line) {
    line.clear();
    bool oversized = false;
    int character = EOF;
    while ((character = std::fgetc(configuration)) != EOF && character != '\n') {
        if (line.size() < 32768) line.push_back(static_cast<char>(character));
        else oversized = true;
    }
    if (oversized) { line.clear(); return LineResult::Oversized; }
    return character == EOF && line.empty() ? LineResult::End : LineResult::Complete;
}

inline std::wstring DecodePath(std::string line) {
    if (line.compare(0, 3, "\xef\xbb\xbf") == 0) line.erase(0, 3);
    size_t begin = 0;
    while (begin < line.size() && std::isspace(static_cast<unsigned char>(line[begin]))) ++begin;
    size_t end = line.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(line[end - 1]))) --end;
    if (begin == end || line[begin] == '#' || line.find('\0') != std::string::npos) return {};
    line = line.substr(begin, end - begin);
    UINT encoding = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    int required = MultiByteToWideChar(encoding, flags, line.data(), static_cast<int>(line.size()), nullptr, 0);
    if (required == 0) {
        encoding = CP_ACP;
        flags = 0;
        required = MultiByteToWideChar(encoding, flags, line.data(), static_cast<int>(line.size()), nullptr, 0);
    }
    if (required <= 0) return {};
    std::vector<wchar_t> buffer(required);
    if (MultiByteToWideChar(encoding, flags, line.data(), static_cast<int>(line.size()), buffer.data(), required) != required) return {};
    return std::wstring(buffer.data(), required);
}

// ============================================================
// DESCRIBE A VALIDATED MAPPED PE IMAGE AND ITS IMPORT DIRECTORY
// Never subtract from an empty import count or scan beyond SizeOfImage.
// ============================================================
struct ImageView {
    unsigned char* base = nullptr;
    size_t length = 0;
    IMAGE_NT_HEADERS* headers = nullptr;
    bool Contains(size_t offset, size_t bytes) const {
        return offset <= length && bytes <= length - offset;
    }
    bool StringAt(DWORD offset) const {
        return Contains(offset, 1) && std::memchr(base + offset, 0, length - offset) != nullptr;
    }
};

inline bool DescribeImage(HMODULE module, ImageView& image) {
    image = {};
    MEMORY_BASIC_INFORMATION region = {};
    if (!module || !VirtualQuery(module, &region, sizeof(region)) || region.State != MEM_COMMIT ||
        (region.Protect & (PAGE_NOACCESS | PAGE_GUARD)) || region.RegionSize < sizeof(IMAGE_NT_HEADERS)) return false;
    auto* base = reinterpret_cast<unsigned char*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<size_t>(dos->e_lfanew) > region.RegionSize - sizeof(IMAGE_NT_HEADERS)) return false;
    auto* headers = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (headers->Signature != IMAGE_NT_SIGNATURE || headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ||
        headers->OptionalHeader.SizeOfImage < sizeof(IMAGE_NT_HEADERS)) return false;
    image.base = base;
    image.length = headers->OptionalHeader.SizeOfImage;
    image.headers = headers;
    return image.Contains(dos->e_lfanew, sizeof(IMAGE_NT_HEADERS));
}

inline bool ImportDirectory(const ImageView& image, IMAGE_IMPORT_DESCRIPTOR*& descriptors, size_t& count) {
    descriptors = nullptr;
    count = 0;
    if (!image.headers || image.headers->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT) return false;
    const auto& directory = image.headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!directory.VirtualAddress || directory.Size < sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
        !image.Contains(directory.VirtualAddress, directory.Size)) return false;
    descriptors = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.base + directory.VirtualAddress);
    count = directory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    return true;
}

// ============================================================
// TEMPORARILY MAKE ONE IMPORT SLOT WRITABLE AND RESTORE ITS FLAGS
// Serialize only the short memory-write operation; never hold this lock while loading DLLs.
// ============================================================
static SRWLOCK import_write_lock = SRWLOCK_INIT;
class ImportWrite {
public:
    explicit ImportWrite(void* slot) : slot_(slot) {
        AcquireSRWLockExclusive(&import_write_lock);
        MEMORY_BASIC_INFORMATION region = {};
        if (!VirtualQuery(slot, &region, sizeof(region)) || region.State != MEM_COMMIT ||
            (region.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return;
        const size_t offset = reinterpret_cast<size_t>(slot) - reinterpret_cast<size_t>(region.BaseAddress);
        if (offset > region.RegionSize || sizeof(size_t) > region.RegionSize - offset) return;
        const DWORD protection = region.Protect & 0xff;
        const bool executable = protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
            protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
        ready_ = VirtualProtect(slot_, sizeof(size_t), executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, &previous_) != FALSE;
    }
    ~ImportWrite() {
        if (ready_) {
            DWORD ignored = 0;
            if (!VirtualProtect(slot_, sizeof(size_t), previous_, &ignored))
                OutputDebugStringW(L"Simple DLL Loader: import protection restoration failed.\n");
        }
        ReleaseSRWLockExclusive(&import_write_lock);
    }
    bool Ready() const { return ready_; }
    ImportWrite(const ImportWrite&) = delete;
    ImportWrite& operator=(const ImportWrite&) = delete;
private:
    void* slot_ = nullptr;
    DWORD previous_ = 0;
    bool ready_ = false;
};

} // namespace loader_security
