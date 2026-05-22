#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#include <winhttp.h>
#include <wtsapi32.h>
#include <rpc.h>

#include <algorithm>
#include <array>
#include <deque>
#include <cstdint>
#include <malloc.h>
#include <fstream>
#include <chrono>
#include <cwctype>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <bcrypt.h>

#include "shared.h"

extern "C" {
#include "tray_rpc_h.h"
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size);
extern "C" void __RPC_USER midl_user_free(void* pointer);

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
CRITICAL_SECTION g_process_lock;
CRITICAL_SECTION g_auth_lock;
std::vector<PROCESS_INFORMATION> g_tray_processes;
HANDLE g_refresh_thread = nullptr;
HANDLE g_schedule_thread = nullptr;
HANDLE g_monitor_thread = nullptr;
HANDLE g_monitor_stop_event = nullptr;
CRITICAL_SECTION g_av_lock;
CRITICAL_SECTION g_schedule_lock;

struct AuthState {
    bool authenticated = false;
    std::wstring login;
    std::wstring accessToken;
    std::wstring refreshToken;
    ULONGLONG nextTokenRefreshTick = 0;

    bool hasLicense = false;
    std::wstring licenseTicket;
    std::wstring licenseExpiresAt;
    ULONGLONG nextLicenseRefreshTick = 0;
};

AuthState g_auth;

enum class ObjectType : unsigned char {
    PeFile = 1,
    Script = 2
};

struct AvRecord {
    uint64_t prefix = 0;
    uint32_t length = 0;
    std::vector<unsigned char> signature_bytes;
    std::array<unsigned char, 32> signature_hash{};
    uint64_t offset_begin = 0;
    uint64_t offset_end = 0;
    ObjectType object_type = ObjectType::PeFile;
    std::array<unsigned char, 32> record_signature{};
    std::wstring name;
};

struct AhoNode {
    std::map<unsigned char, size_t> next;
    size_t failure = 0;
    std::vector<size_t> outputs;
};

struct AvDatabase {
    bool loaded = false;
    std::wstring release_date;
    std::map<uint64_t, std::vector<AvRecord>> records;
    std::vector<AvRecord> all_records;
    std::vector<AhoNode> aho_nodes;
};

struct ScheduleState {
    bool enabled = false;
    long interval_minutes = 0;
    std::wstring path;
    ULONGLONG next_scan_tick = 0;
    std::wstring last_result;
};

AvDatabase g_av_database;
ScheduleState g_schedule;
std::wstring g_monitor_path;
std::wstring g_monitor_last_result;

std::wstring GetCurrentDirectoryForModule();

constexpr wchar_t kDemoLogin[] = L"test";
constexpr wchar_t kDemoPassword[] = L"test";
constexpr wchar_t kDemoActivationCode[] = L"DEMO-KEY";
constexpr wchar_t kDemoExpiredActivationCode[] = L"EXPIRED-KEY";
constexpr wchar_t kDemoBlockedActivationCode[] = L"BLOCKED-KEY";
constexpr wchar_t kDemoAccessToken[] = L"demo-access-token";
constexpr wchar_t kDemoRefreshToken[] = L"demo-refresh-token";
constexpr wchar_t kDemoLicenseTicket[] = L"demo-license-ticket";
constexpr wchar_t kDemoLicenseExpiresAt[] = L"2026-12-31T23:59:59Z";

PSECURITY_DESCRIPTOR CreateProtectedProcessSecurityDescriptor() {
    PSECURITY_DESCRIPTOR security_descriptor = nullptr;
    constexpr wchar_t kProtectedProcessSddl[] =
        L"D:P"
        L"(A;;GA;;;SY)"
        L"(A;;GA;;;BA)"
        L"(A;;GR;;;IU)"
        L"(A;;GR;;;BU)";

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kProtectedProcessSddl,
            SDDL_REVISION_1,
            &security_descriptor,
            nullptr)) {
        return nullptr;
    }

    return security_descriptor;
}

void ApplyProtectedDaclToCurrentProcess() {
    PSECURITY_DESCRIPTOR security_descriptor = CreateProtectedProcessSecurityDescriptor();
    if (!security_descriptor) {
        return;
    }

    PACL dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    if (GetSecurityDescriptorDacl(security_descriptor, &dacl_present, &dacl, &dacl_defaulted) &&
        dacl_present) {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            dacl,
            nullptr
        );
    }

    LocalFree(security_descriptor);
}

void WriteLog(const std::wstring& message) {
    const std::wstring log_path = GetCurrentDirectoryForModule() + L"\\ZIOVPOService.log";
    std::wofstream log(log_path.c_str(), std::ios::app);
    if (!log) {
        return;
    }

    SYSTEMTIME now{};
    GetLocalTime(&now);
    log << L"["
        << now.wYear << L"-" << now.wMonth << L"-" << now.wDay << L" "
        << now.wHour << L":" << now.wMinute << L":" << now.wSecond << L"] "
        << message << L"\n";
}

void WriteLastErrorLog(const std::wstring& operation) {
    WriteLog(operation + L" failed, error=" + std::to_wstring(GetLastError()));
}

std::wstring GetEnvOrDefault(const wchar_t* name, const wchar_t* fallback) {
    wchar_t buffer[2048]{};
    DWORD length = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(_countof(buffer)));
    if (length == 0 || length >= _countof(buffer)) {
        return fallback;
    }
    return buffer;
}

std::string ToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring FromUtf8(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

std::wstring JsonEscape(const std::wstring& value) {
    std::wstring escaped;
    for (wchar_t ch : value) {
        switch (ch) {
        case L'\\':
            escaped += L"\\\\";
            break;
        case L'"':
            escaped += L"\\\"";
            break;
        case L'\n':
            escaped += L"\\n";
            break;
        case L'\r':
            escaped += L"\\r";
            break;
        case L'\t':
            escaped += L"\\t";
            break;
        default:
            escaped += ch;
            break;
        }
    }
    return escaped;
}

std::wstring ExtractJsonString(const std::wstring& json, const std::wstring& key) {
    const std::wstring marker = L"\"" + key + L"\"";
    size_t pos = json.find(marker);
    if (pos == std::wstring::npos) {
        return {};
    }
    pos = json.find(L':', pos);
    if (pos == std::wstring::npos) {
        return {};
    }
    pos = json.find(L'"', pos);
    if (pos == std::wstring::npos) {
        return {};
    }
    ++pos;

    std::wstring result;
    bool escape = false;
    for (; pos < json.size(); ++pos) {
        wchar_t ch = json[pos];
        if (escape) {
            result += ch;
            escape = false;
            continue;
        }
        if (ch == L'\\') {
            escape = true;
            continue;
        }
        if (ch == L'"') {
            break;
        }
        result += ch;
    }
    return result;
}

long ExtractJsonLong(const std::wstring& json, const std::wstring& key, long fallback) {
    const std::wstring marker = L"\"" + key + L"\"";
    size_t pos = json.find(marker);
    if (pos == std::wstring::npos) {
        return fallback;
    }
    pos = json.find(L':', pos);
    if (pos == std::wstring::npos) {
        return fallback;
    }
    ++pos;
    while (pos < json.size() && iswspace(json[pos])) {
        ++pos;
    }
    wchar_t* end = nullptr;
    long value = wcstol(json.c_str() + pos, &end, 10);
    return end == json.c_str() + pos ? fallback : value;
}

ULONGLONG DelayFromSeconds(long seconds, long fallbackSeconds) {
    long effective = seconds > 30 ? seconds - 30 : fallbackSeconds;
    return GetTickCount64() + static_cast<ULONGLONG>(effective) * 1000ULL;
}

std::vector<unsigned char> ToBytes(const char* text) {
    std::vector<unsigned char> bytes;
    while (*text) {
        bytes.push_back(static_cast<unsigned char>(*text));
        ++text;
    }
    return bytes;
}

uint64_t ReadPrefix(const unsigned char* bytes) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(bytes[i]) << (i * 8);
    }
    return value;
}

std::array<unsigned char, 32> Sha256(const std::vector<unsigned char>& bytes) {
    std::array<unsigned char, 32> hash{};
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash_handle = nullptr;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return hash;
    }
    if (BCryptCreateHash(algorithm, &hash_handle, nullptr, 0, nullptr, 0, 0) == 0) {
        BCryptHashData(hash_handle, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0);
        BCryptFinishHash(hash_handle, hash.data(), static_cast<ULONG>(hash.size()), 0);
        BCryptDestroyHash(hash_handle);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return hash;
}

void AppendUint64(std::vector<unsigned char>& bytes, uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        bytes.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
    }
}

void AppendUint32(std::vector<unsigned char>& bytes, uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        bytes.push_back(static_cast<unsigned char>((value >> (i * 8)) & 0xff));
    }
}

std::array<unsigned char, 32> MakeRecordSignature(const AvRecord& record) {
    std::vector<unsigned char> bytes;
    AppendUint64(bytes, record.prefix);
    AppendUint32(bytes, record.length);
    bytes.insert(bytes.end(), record.signature_hash.begin(), record.signature_hash.end());
    AppendUint64(bytes, record.offset_begin);
    AppendUint64(bytes, record.offset_end);
    bytes.push_back(static_cast<unsigned char>(record.object_type));
    return Sha256(bytes);
}

AvRecord MakeAvRecord(const char* signature, ObjectType object_type, uint64_t offset_begin, uint64_t offset_end, const std::wstring& name) {
    std::vector<unsigned char> signature_bytes = ToBytes(signature);
    AvRecord record;
    record.prefix = ReadPrefix(signature_bytes.data());
    record.length = static_cast<uint32_t>(signature_bytes.size());
    record.signature_bytes = signature_bytes;
    record.signature_hash = Sha256(signature_bytes);
    record.offset_begin = offset_begin;
    record.offset_end = offset_end;
    record.object_type = object_type;
    record.name = name;
    record.record_signature = MakeRecordSignature(record);
    return record;
}

void AddAvRecord(const AvRecord& record) {
    g_av_database.records[record.prefix].push_back(record);
    g_av_database.all_records.push_back(record);
}

void BuildAhoCorasickAutomaton() {
    g_av_database.aho_nodes.clear();
    g_av_database.aho_nodes.push_back(AhoNode{});

    for (size_t recordIndex = 0; recordIndex < g_av_database.all_records.size(); ++recordIndex) {
        const std::vector<unsigned char>& pattern = g_av_database.all_records[recordIndex].signature_bytes;
        size_t state = 0;
        for (unsigned char byte : pattern) {
            auto [it, inserted] = g_av_database.aho_nodes[state].next.emplace(byte, g_av_database.aho_nodes.size());
            if (inserted) {
                g_av_database.aho_nodes.push_back(AhoNode{});
            }
            state = it->second;
        }
        g_av_database.aho_nodes[state].outputs.push_back(recordIndex);
    }

    std::deque<size_t> queue;
    for (const auto& [byte, nextState] : g_av_database.aho_nodes[0].next) {
        UNREFERENCED_PARAMETER(byte);
        g_av_database.aho_nodes[nextState].failure = 0;
        queue.push_back(nextState);
    }

    while (!queue.empty()) {
        size_t state = queue.front();
        queue.pop_front();

        for (const auto& [byte, nextState] : g_av_database.aho_nodes[state].next) {
            size_t failure = g_av_database.aho_nodes[state].failure;
            while (failure != 0 && g_av_database.aho_nodes[failure].next.find(byte) == g_av_database.aho_nodes[failure].next.end()) {
                failure = g_av_database.aho_nodes[failure].failure;
            }

            auto failureTransition = g_av_database.aho_nodes[failure].next.find(byte);
            if (failureTransition != g_av_database.aho_nodes[failure].next.end() && failureTransition->second != nextState) {
                g_av_database.aho_nodes[nextState].failure = failureTransition->second;
            } else {
                g_av_database.aho_nodes[nextState].failure = 0;
            }

            const std::vector<size_t>& failureOutputs = g_av_database.aho_nodes[g_av_database.aho_nodes[nextState].failure].outputs;
            g_av_database.aho_nodes[nextState].outputs.insert(
                g_av_database.aho_nodes[nextState].outputs.end(),
                failureOutputs.begin(),
                failureOutputs.end()
            );
            queue.push_back(nextState);
        }
    }
}

void LoadAvDatabaseIfNeeded() {
    EnterCriticalSection(&g_av_lock);
    if (!g_av_database.loaded) {
        g_av_database.release_date = L"2026-05-17";
        g_av_database.records.clear();
        g_av_database.all_records.clear();
        AddAvRecord(MakeAvRecord("EICAR-ZIOVPO-PE", ObjectType::PeFile, 0, 1024 * 1024, L"Demo.PE.EicarZIOVPO"));
        AddAvRecord(MakeAvRecord("ZIOVPO-SCRIPT-MALWARE", ObjectType::Script, 0, 1024 * 1024, L"Demo.Script.ZIOVPO"));
        BuildAhoCorasickAutomaton();
        g_av_database.loaded = true;
        WriteLog(L"AV database loaded, records=" + std::to_wstring(g_av_database.records.size()));
    }
    LeaveCriticalSection(&g_av_lock);
}

size_t GetAvRecordCountUnlocked() {
    size_t count = 0;
    for (const auto& [prefix, records] : g_av_database.records) {
        UNREFERENCED_PARAMETER(prefix);
        count += records.size();
    }
    return count;
}

bool HasLicenseTicket() {
    bool hasLicense = false;
    EnterCriticalSection(&g_auth_lock);
    hasLicense = g_auth.hasLicense;
    LeaveCriticalSection(&g_auth_lock);
    return hasLicense;
}

ObjectType DetectObjectType(const std::wstring& path, const std::vector<unsigned char>& bytes) {
    if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
        return ObjectType::PeFile;
    }

    const size_t dot = path.find_last_of(L'.');
    std::wstring extension = dot == std::wstring::npos ? L"" : path.substr(dot);
    std::transform(extension.begin(), extension.end(), extension.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(towlower(ch));
    });
    if (extension == L".ps1" || extension == L".js" || extension == L".py" || extension == L".bat" || extension == L".cmd" || extension == L".txt") {
        return ObjectType::Script;
    }

    return ObjectType::PeFile;
}

bool ReadFileBytes(const std::wstring& path, std::vector<unsigned char>& bytes, std::wstring& error) {
    bytes.clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = L"Cannot open file, error=" + std::to_wstring(GetLastError());
        return false;
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 64LL * 1024LL * 1024LL) {
        CloseHandle(file);
        error = L"File is too large for demo scanner";
        return false;
    }

    bytes.resize(static_cast<size_t>(size.QuadPart));
    DWORD read = 0;
    BOOL ok = bytes.empty() || ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok) {
        error = L"Cannot read file, error=" + std::to_wstring(GetLastError());
        return false;
    }
    bytes.resize(read);
    return true;
}

bool ScanBytes(const std::wstring& path, const std::vector<unsigned char>& bytes, std::wstring& detection) {
    detection.clear();
    if (bytes.empty()) {
        return false;
    }

    ObjectType object_type = DetectObjectType(path, bytes);
    size_t state = 0;

    for (size_t position = 0; position < bytes.size(); ++position) {
        unsigned char byte = bytes[position];

        EnterCriticalSection(&g_av_lock);
        while (state != 0 && g_av_database.aho_nodes[state].next.find(byte) == g_av_database.aho_nodes[state].next.end()) {
            state = g_av_database.aho_nodes[state].failure;
        }
        auto transition = g_av_database.aho_nodes[state].next.find(byte);
        if (transition != g_av_database.aho_nodes[state].next.end()) {
            state = transition->second;
        }
        std::vector<AvRecord> candidates;
        for (size_t recordIndex : g_av_database.aho_nodes[state].outputs) {
            if (recordIndex < g_av_database.all_records.size()) {
                candidates.push_back(g_av_database.all_records[recordIndex]);
            }
        }
        LeaveCriticalSection(&g_av_lock);

        for (const AvRecord& record : candidates) {
            if (position + 1 < record.length) {
                continue;
            }
            size_t start = position + 1 - record.length;
            if (record.object_type != object_type) {
                continue;
            }
            if (start < record.offset_begin || start > record.offset_end) {
                continue;
            }
            if (start + record.length > bytes.size()) {
                continue;
            }

            std::vector<unsigned char> signature(bytes.begin() + start, bytes.begin() + start + record.length);
            if (Sha256(signature) == record.signature_hash) {
                detection = record.name;
                return true;
            }
        }
    }

    return false;
}

long EnsureAvReady(std::wstring& error) {
    if (!HasLicenseTicket()) {
        error = L"License ticket is missing";
        return ERROR_NOT_READY;
    }
    LoadAvDatabaseIfNeeded();
    return 0;
}

long ScanSingleFile(const std::wstring& path, bool& infected, std::wstring& detection, std::wstring& error) {
    infected = false;
    detection.clear();
    long ready = EnsureAvReady(error);
    if (ready != 0) {
        return ready;
    }

    std::vector<unsigned char> bytes;
    if (!ReadFileBytes(path, bytes, error)) {
        return ERROR_OPEN_FAILED;
    }

    infected = ScanBytes(path, bytes, detection);
    return 0;
}

void AppendScanLine(std::wstringstream& report, const std::wstring& path, bool infected, const std::wstring& detection) {
    report << (infected ? L"[INFECTED] " : L"[CLEAN] ") << path;
    if (infected) {
        report << L" (" << detection << L")";
    }
    report << L"\r\n";
}

void ScanDirectoryRecursive(
    const std::wstring& path,
    std::wstringstream& report,
    long& scanned,
    long& infectedCount,
    long maxFiles = 0) {
    if (maxFiles > 0 && scanned >= maxFiles) {
        return;
    }

    std::wstring mask = path + L"\\*";
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(mask.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) {
            continue;
        }
        std::wstring child = path + L"\\" + data.cFileName;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanDirectoryRecursive(child, report, scanned, infectedCount, maxFiles);
            continue;
        }
        if (maxFiles > 0 && scanned >= maxFiles) {
            break;
        }

        bool infected = false;
        std::wstring detection;
        std::wstring error;
        if (ScanSingleFile(child, infected, detection, error) == 0) {
            ++scanned;
            if (infected) {
                ++infectedCount;
                AppendScanLine(report, child, true, detection);
            }
        }
    } while ((maxFiles <= 0 || scanned < maxFiles) && FindNextFileW(find, &data));

    FindClose(find);
}

long ScanPathDirectory(const std::wstring& path, std::wstring& result, std::wstring& error) {
    long ready = EnsureAvReady(error);
    if (ready != 0) {
        return ready;
    }

    long scanned = 0;
    long infected = 0;
    std::wstringstream report;
    ScanDirectoryRecursive(path, report, scanned, infected);
    result = L"Scanned files: " + std::to_wstring(scanned) + L", infected: " + std::to_wstring(infected) + L"\r\n" + report.str();
    error.clear();
    return 0;
}

long ScanAllFixedDrivesInternal(std::wstring& result, std::wstring& error) {
    long ready = EnsureAvReady(error);
    if (ready != 0) {
        return ready;
    }

    wchar_t drives[512]{};
    DWORD length = GetLogicalDriveStringsW(static_cast<DWORD>(_countof(drives)), drives);
    if (length == 0 || length > _countof(drives)) {
        error = L"Cannot enumerate drives";
        return ERROR_NOT_READY;
    }

    constexpr long kMaxFilesPerDriveForUiScan = 200;
    long totalScanned = 0;
    long totalInfected = 0;
    std::wstringstream report;
    for (wchar_t* drive = drives; *drive; drive += wcslen(drive) + 1) {
        if (GetDriveTypeW(drive) != DRIVE_FIXED) {
            continue;
        }

        long scanned = 0;
        long infected = 0;
        report << L"Drive " << drive << L" (demo limit " << kMaxFilesPerDriveForUiScan << L" files)\r\n";
        ScanDirectoryRecursive(drive, report, scanned, infected, kMaxFilesPerDriveForUiScan);
        totalScanned += scanned;
        totalInfected += infected;
    }

    result = L"Fixed drives scanned files: " + std::to_wstring(totalScanned) +
        L", infected: " + std::to_wstring(totalInfected) +
        L", per-drive demo limit: " + std::to_wstring(kMaxFilesPerDriveForUiScan) +
        L"\r\n" + report.str();
    error.clear();
    return 0;
}

DWORD WINAPI ScheduleThreadProc(void*) {
    while (WaitForSingleObject(g_stop_event, 1000) == WAIT_TIMEOUT) {
        bool shouldScan = false;
        std::wstring path;

        EnterCriticalSection(&g_schedule_lock);
        if (g_schedule.enabled && g_schedule.next_scan_tick != 0 && GetTickCount64() >= g_schedule.next_scan_tick) {
            shouldScan = true;
            path = g_schedule.path;
            g_schedule.next_scan_tick = GetTickCount64() + static_cast<ULONGLONG>(g_schedule.interval_minutes) * 60ULL * 1000ULL;
        }
        LeaveCriticalSection(&g_schedule_lock);

        if (shouldScan) {
            std::wstring result;
            std::wstring error;
            DWORD attributes = GetFileAttributesW(path.c_str());
            long code = ERROR_INVALID_PARAMETER;
            if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
                code = ScanPathDirectory(path, result, error);
            } else if (attributes != INVALID_FILE_ATTRIBUTES) {
                bool infected = false;
                std::wstring detection;
                code = ScanSingleFile(path, infected, detection, error);
                result = infected
                    ? L"Scheduled scan detected malware: " + detection
                    : L"Scheduled scan completed: file is clean";
            }
            if (code != 0) {
                result = L"Scheduled scan failed: " + error;
            }

            EnterCriticalSection(&g_schedule_lock);
            g_schedule.last_result = result;
            LeaveCriticalSection(&g_schedule_lock);
        }
    }
    return 0;
}

DWORD WINAPI MonitorThreadProc(void*) {
    while (WaitForSingleObject(g_monitor_stop_event, 1000) == WAIT_TIMEOUT) {
        std::wstring path;
        EnterCriticalSection(&g_schedule_lock);
        path = g_monitor_path;
        LeaveCriticalSection(&g_schedule_lock);
        if (path.empty()) {
            continue;
        }

        HANDLE directory = CreateFileW(
            path.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr
        );
        if (directory == INVALID_HANDLE_VALUE) {
            Sleep(3000);
            continue;
        }

        unsigned char buffer[4096]{};
        DWORD bytes_returned = 0;
        OVERLAPPED overlapped{};
        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!overlapped.hEvent) {
            CloseHandle(directory);
            continue;
        }

        BOOL ok = ReadDirectoryChangesW(
            directory,
            buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION,
            &bytes_returned,
            &overlapped,
            nullptr
        );

        if (!ok && GetLastError() != ERROR_IO_PENDING) {
            CloseHandle(overlapped.hEvent);
            CloseHandle(directory);
            continue;
        }

        HANDLE waitHandles[] = {g_monitor_stop_event, overlapped.hEvent};
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        if (waitResult == WAIT_OBJECT_0) {
            CancelIo(directory);
            CloseHandle(overlapped.hEvent);
            CloseHandle(directory);
            break;
        }

        if (waitResult != WAIT_OBJECT_0 + 1 ||
            !GetOverlappedResult(directory, &overlapped, &bytes_returned, FALSE) ||
            bytes_returned == 0) {
            CloseHandle(overlapped.hEvent);
            CloseHandle(directory);
            continue;
        }

        CloseHandle(overlapped.hEvent);
        CloseHandle(directory);

        std::wstring result;
        std::wstring error;
        ScanPathDirectory(path, result, error);
        EnterCriticalSection(&g_schedule_lock);
        g_monitor_last_result = error.empty() ? result : L"Monitor scan failed: " + error;
        LeaveCriticalSection(&g_schedule_lock);
    }
    return 0;
}

bool HttpRequestJson(
    const std::wstring& method,
    const std::wstring& path,
    const std::wstring& body,
    const std::wstring& bearerToken,
    DWORD& statusCode,
    std::wstring& response) {
    response.clear();
    statusCode = 0;

    const std::wstring baseUrl = GetEnvOrDefault(L"ZIOVPO_API_BASE_URL", L"https://localhost:8443");
    const std::wstring fullUrl = baseUrl + path;

    URL_COMPONENTSW url{};
    wchar_t host[256]{};
    wchar_t urlPath[2048]{};
    url.dwStructSize = sizeof(url);
    url.lpszHostName = host;
    url.dwHostNameLength = static_cast<DWORD>(_countof(host));
    url.lpszUrlPath = urlPath;
    url.dwUrlPathLength = static_cast<DWORD>(_countof(urlPath));

    if (!WinHttpCrackUrl(fullUrl.c_str(), 0, 0, &url)) {
        WriteLastErrorLog(L"WinHttpCrackUrl");
        return false;
    }

    HINTERNET session = WinHttpOpen(
        L"ZIOVPOService/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!session) {
        WriteLastErrorLog(L"WinHttpOpen");
        return false;
    }

    HINTERNET connection = WinHttpConnect(session, std::wstring(host, url.dwHostNameLength).c_str(), url.nPort, 0);
    if (!connection) {
        WriteLastErrorLog(L"WinHttpConnect");
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD flags = url.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(
        connection,
        method.c_str(),
        std::wstring(urlPath, url.dwUrlPathLength).c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );
    if (!request) {
        WriteLastErrorLog(L"WinHttpOpenRequest");
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearerToken.empty()) {
        headers += L"Authorization: Bearer " + bearerToken + L"\r\n";
    }

    std::string utf8Body = ToUtf8(body);
    BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        utf8Body.empty() ? WINHTTP_NO_REQUEST_DATA : utf8Body.data(),
        static_cast<DWORD>(utf8Body.size()),
        static_cast<DWORD>(utf8Body.size()),
        0
    );
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        WriteLastErrorLog(L"WinHTTP request");
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusSize,
        WINHTTP_NO_HEADER_INDEX
    );

    std::string responseBytes;
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
        std::string buffer(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, buffer.data(), available, &read)) {
            break;
        }
        buffer.resize(read);
        responseBytes += buffer;
    }

    response = FromUtf8(responseBytes);
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return true;
}

void ClearAuthState() {
    EnterCriticalSection(&g_auth_lock);
    g_auth = AuthState{};
    LeaveCriticalSection(&g_auth_lock);
}

bool IsDemoAccessToken(const std::wstring& accessToken) {
    return accessToken == kDemoAccessToken;
}

bool IsDemoRefreshToken(const std::wstring& refreshToken) {
    return refreshToken == kDemoRefreshToken;
}

void SetDemoAuthenticatedUser() {
    EnterCriticalSection(&g_auth_lock);
    g_auth.authenticated = true;
    g_auth.login = kDemoLogin;
    g_auth.accessToken = kDemoAccessToken;
    g_auth.refreshToken = kDemoRefreshToken;
    g_auth.nextTokenRefreshTick = DelayFromSeconds(120, 120);
    g_auth.hasLicense = false;
    g_auth.licenseTicket.clear();
    g_auth.licenseExpiresAt.clear();
    g_auth.nextLicenseRefreshTick = 0;
    LeaveCriticalSection(&g_auth_lock);
}

long TryDemoAuthenticate(const std::wstring& login, const std::wstring& password, std::wstring& error) {
    if (login != kDemoLogin || password != kDemoPassword) {
        error = L"Invalid login or password";
        return ERROR_LOGON_FAILURE;
    }

    SetDemoAuthenticatedUser();
    error.clear();
    return 0;
}

long AuthenticateUser(const std::wstring& login, const std::wstring& password, std::wstring& error) {
    const std::wstring path = GetEnvOrDefault(L"ZIOVPO_LOGIN_PATH", L"/api/auth/login");
    const std::wstring body =
        L"{\"login\":\"" + JsonEscape(login) + L"\",\"password\":\"" + JsonEscape(password) + L"\"}";

    DWORD status = 0;
    std::wstring response;
    if (!HttpRequestJson(L"POST", path, body, L"", status, response) || status < 200 || status >= 300) {
        long demoResult = TryDemoAuthenticate(login, password, error);
        if (demoResult == 0) {
            WriteLog(L"Using built-in demo authentication fallback");
            return 0;
        }

        error = !response.empty() ? response : error;
        return status ? static_cast<long>(status) : demoResult;
    }

    std::wstring access = ExtractJsonString(response, L"accessToken");
    std::wstring refresh = ExtractJsonString(response, L"refreshToken");
    std::wstring displayLogin = ExtractJsonString(response, L"login");
    if (displayLogin.empty()) {
        displayLogin = ExtractJsonString(response, L"email");
    }
    if (displayLogin.empty()) {
        displayLogin = login;
    }
    if (access.empty() || refresh.empty()) {
        error = L"Authentication response does not contain JWT tokens";
        return ERROR_INVALID_DATA;
    }

    EnterCriticalSection(&g_auth_lock);
    g_auth.authenticated = true;
    g_auth.login = displayLogin;
    g_auth.accessToken = access;
    g_auth.refreshToken = refresh;
    g_auth.nextTokenRefreshTick = DelayFromSeconds(ExtractJsonLong(response, L"accessExpiresIn", 600), 600);
    g_auth.hasLicense = false;
    g_auth.licenseTicket.clear();
    g_auth.licenseExpiresAt.clear();
    g_auth.nextLicenseRefreshTick = 0;
    LeaveCriticalSection(&g_auth_lock);

    error.clear();
    return 0;
}

long RefreshTokens() {
    std::wstring refreshToken;
    EnterCriticalSection(&g_auth_lock);
    refreshToken = g_auth.refreshToken;
    LeaveCriticalSection(&g_auth_lock);
    if (refreshToken.empty()) {
        return ERROR_NOT_LOGGED_ON;
    }
    if (IsDemoRefreshToken(refreshToken)) {
        EnterCriticalSection(&g_auth_lock);
        g_auth.accessToken = kDemoAccessToken;
        g_auth.refreshToken = kDemoRefreshToken;
        g_auth.nextTokenRefreshTick = DelayFromSeconds(120, 120);
        LeaveCriticalSection(&g_auth_lock);
        return 0;
    }

    const std::wstring path = GetEnvOrDefault(L"ZIOVPO_REFRESH_PATH", L"/api/auth/refresh");
    const std::wstring body = L"{\"refreshToken\":\"" + JsonEscape(refreshToken) + L"\"}";

    DWORD status = 0;
    std::wstring response;
    if (!HttpRequestJson(L"POST", path, body, L"", status, response) || status < 200 || status >= 300) {
        ClearAuthState();
        return static_cast<long>(status ? status : ERROR_NOT_CONNECTED);
    }

    std::wstring access = ExtractJsonString(response, L"accessToken");
    std::wstring refresh = ExtractJsonString(response, L"refreshToken");
    if (access.empty() || refresh.empty()) {
        ClearAuthState();
        return ERROR_INVALID_DATA;
    }

    EnterCriticalSection(&g_auth_lock);
    g_auth.accessToken = access;
    g_auth.refreshToken = refresh;
    g_auth.nextTokenRefreshTick = DelayFromSeconds(ExtractJsonLong(response, L"accessExpiresIn", 600), 600);
    LeaveCriticalSection(&g_auth_lock);
    return 0;
}

long QueryLicenseStatus(std::wstring& error) {
    std::wstring accessToken;
    EnterCriticalSection(&g_auth_lock);
    accessToken = g_auth.accessToken;
    LeaveCriticalSection(&g_auth_lock);
    if (accessToken.empty()) {
        error = L"User is not authenticated";
        return ERROR_NOT_LOGGED_ON;
    }
    if (IsDemoAccessToken(accessToken)) {
        EnterCriticalSection(&g_auth_lock);
        g_auth.nextLicenseRefreshTick = g_auth.hasLicense ? DelayFromSeconds(120, 120) : 0;
        LeaveCriticalSection(&g_auth_lock);
        error.clear();
        return 0;
    }

    const std::wstring path = GetEnvOrDefault(L"ZIOVPO_LICENSE_STATUS_PATH", L"/api/license/status");
    DWORD status = 0;
    std::wstring response;
    if (!HttpRequestJson(L"GET", path, L"", accessToken, status, response) || status < 200 || status >= 300) {
        error = !response.empty() ? response : L"License status request failed";
        return static_cast<long>(status ? status : ERROR_NOT_CONNECTED);
    }

    std::wstring ticket = ExtractJsonString(response, L"ticket");
    std::wstring expiresAt = ExtractJsonString(response, L"expiresAt");
    bool hasLicense = !ticket.empty() || ExtractJsonLong(response, L"hasLicense", 0) != 0;

    EnterCriticalSection(&g_auth_lock);
    g_auth.hasLicense = hasLicense;
    g_auth.licenseTicket = ticket;
    g_auth.licenseExpiresAt = expiresAt;
    g_auth.nextLicenseRefreshTick = DelayFromSeconds(ExtractJsonLong(response, L"licenseExpiresIn", 300), 300);
    LeaveCriticalSection(&g_auth_lock);
    if (hasLicense) {
        LoadAvDatabaseIfNeeded();
    }

    error.clear();
    return 0;
}

long ActivateLicense(const std::wstring& code, std::wstring& error) {
    std::wstring accessToken;
    EnterCriticalSection(&g_auth_lock);
    accessToken = g_auth.accessToken;
    LeaveCriticalSection(&g_auth_lock);
    if (accessToken.empty()) {
        error = L"User is not authenticated";
        return ERROR_NOT_LOGGED_ON;
    }
    if (IsDemoAccessToken(accessToken)) {
        if (code == kDemoExpiredActivationCode || code == kDemoBlockedActivationCode) {
            EnterCriticalSection(&g_auth_lock);
            g_auth.hasLicense = false;
            g_auth.licenseTicket.clear();
            g_auth.licenseExpiresAt.clear();
            g_auth.nextLicenseRefreshTick = 0;
            LeaveCriticalSection(&g_auth_lock);
            error = code == kDemoExpiredActivationCode
                ? L"License expired on server"
                : L"License blocked on server";
            return ERROR_NOT_READY;
        }

        if (code != kDemoActivationCode) {
            error = L"Invalid activation code";
            return ERROR_INVALID_DATA;
        }

        EnterCriticalSection(&g_auth_lock);
        g_auth.hasLicense = true;
        g_auth.licenseTicket = kDemoLicenseTicket;
        g_auth.licenseExpiresAt = kDemoLicenseExpiresAt;
        g_auth.nextLicenseRefreshTick = DelayFromSeconds(120, 120);
        LeaveCriticalSection(&g_auth_lock);
        LoadAvDatabaseIfNeeded();
        error.clear();
        return 0;
    }

    const std::wstring path = GetEnvOrDefault(L"ZIOVPO_ACTIVATE_PATH", L"/api/license/activate");
    const std::wstring body = L"{\"activationCode\":\"" + JsonEscape(code) + L"\"}";

    DWORD status = 0;
    std::wstring response;
    if (!HttpRequestJson(L"POST", path, body, accessToken, status, response) || status < 200 || status >= 300) {
        error = !response.empty() ? response : L"Activation request failed";
        return static_cast<long>(status ? status : ERROR_NOT_CONNECTED);
    }

    std::wstring ticket = ExtractJsonString(response, L"ticket");
    std::wstring expiresAt = ExtractJsonString(response, L"expiresAt");
    if (!ticket.empty()) {
        EnterCriticalSection(&g_auth_lock);
        g_auth.hasLicense = true;
        g_auth.licenseTicket = ticket;
        g_auth.licenseExpiresAt = expiresAt;
        g_auth.nextLicenseRefreshTick = DelayFromSeconds(ExtractJsonLong(response, L"licenseExpiresIn", 300), 300);
        LeaveCriticalSection(&g_auth_lock);
        LoadAvDatabaseIfNeeded();
        error.clear();
        return 0;
    }

    return QueryLicenseStatus(error);
}

DWORD WINAPI RefreshThreadProc(void*) {
    while (WaitForSingleObject(g_stop_event, 1000) == WAIT_TIMEOUT) {
        ULONGLONG now = GetTickCount64();
        bool refreshTokens = false;
        bool refreshLicense = false;

        EnterCriticalSection(&g_auth_lock);
        refreshTokens = g_auth.authenticated &&
            g_auth.nextTokenRefreshTick != 0 &&
            now >= g_auth.nextTokenRefreshTick;
        refreshLicense = g_auth.authenticated &&
            g_auth.hasLicense &&
            g_auth.nextLicenseRefreshTick != 0 &&
            now >= g_auth.nextLicenseRefreshTick;
        LeaveCriticalSection(&g_auth_lock);

        if (refreshTokens) {
            RefreshTokens();
        }
        if (refreshLicense) {
            std::wstring ignored;
            QueryLicenseStatus(ignored);
        }
    }
    return 0;
}

wchar_t* RpcCopyString(const std::wstring& value) {
    size_t bytes = (value.size() + 1) * sizeof(wchar_t);
    wchar_t* copy = static_cast<wchar_t*>(midl_user_allocate(bytes));
    if (!copy) {
        return nullptr;
    }
    wcscpy_s(copy, value.size() + 1, value.c_str());
    return copy;
}

void SetServiceState(DWORD state, DWORD win32_exit_code = NO_ERROR, DWORD wait_hint = 0) {
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32_exit_code;
    g_status.dwWaitHint = wait_hint;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_SESSIONCHANGE : 0;
    SetServiceStatus(g_status_handle, &g_status);
}

std::wstring GetCurrentDirectoryForModule() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring module_path(path);
    const size_t slash = module_path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return L".";
    }
    return module_path.substr(0, slash);
}

std::wstring Quote(const std::wstring& value) {
    return L"\"" + value + L"\"";
}

bool IsProcessRunning(const PROCESS_INFORMATION& process) {
    return WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT;
}

void CloseProcessInfo(PROCESS_INFORMATION& process) {
    if (process.hThread) {
        CloseHandle(process.hThread);
        process.hThread = nullptr;
    }
    if (process.hProcess) {
        CloseHandle(process.hProcess);
        process.hProcess = nullptr;
    }
}

bool HasTrayProcessInSession(DWORD session_id) {
    EnterCriticalSection(&g_process_lock);

    bool found = false;
    for (auto& process : g_tray_processes) {
        DWORD process_session = 0;
        if (process.dwProcessId != 0 &&
            ProcessIdToSessionId(process.dwProcessId, &process_session) &&
            process_session == session_id &&
            IsProcessRunning(process)) {
            found = true;
            break;
        }
    }

    LeaveCriticalSection(&g_process_lock);
    return found;
}

void RememberTrayProcess(const PROCESS_INFORMATION& process) {
    EnterCriticalSection(&g_process_lock);
    g_tray_processes.push_back(process);
    LeaveCriticalSection(&g_process_lock);
}

void CleanupStoppedTrayProcesses() {
    EnterCriticalSection(&g_process_lock);

    auto it = g_tray_processes.begin();
    while (it != g_tray_processes.end()) {
        if (IsProcessRunning(*it)) {
            ++it;
            continue;
        }

        CloseProcessInfo(*it);
        it = g_tray_processes.erase(it);
    }

    LeaveCriticalSection(&g_process_lock);
}

void TerminateTrayProcesses() {
    EnterCriticalSection(&g_process_lock);

    for (auto& process : g_tray_processes) {
        if (process.hProcess && IsProcessRunning(process)) {
            TerminateProcess(process.hProcess, 0);
            WaitForSingleObject(process.hProcess, 3000);
        }
        CloseProcessInfo(process);
    }
    g_tray_processes.clear();

    LeaveCriticalSection(&g_process_lock);
}

void LaunchTrayForSession(DWORD session_id) {
    WriteLog(L"Trying to launch tray for session " + std::to_wstring(session_id));

    if (session_id == 0 || HasTrayProcessInSession(session_id)) {
        WriteLog(L"Skipping session " + std::to_wstring(session_id));
        return;
    }

    HANDLE user_token = nullptr;
    if (!WTSQueryUserToken(session_id, &user_token)) {
        WriteLastErrorLog(L"WTSQueryUserToken for session " + std::to_wstring(session_id));
        return;
    }

    HANDLE primary_token = nullptr;
    if (!DuplicateTokenEx(
            user_token,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &primary_token)) {
        WriteLastErrorLog(L"DuplicateTokenEx");
        CloseHandle(user_token);
        return;
    }
    CloseHandle(user_token);

    void* environment = nullptr;
    CreateEnvironmentBlock(&environment, primary_token, FALSE);

    const std::wstring app_path = GetCurrentDirectoryForModule() + L"\\" + kTrayAppExecutableName;
    std::wstring command_line = Quote(app_path) + L" " + kBackgroundArgument;
    WriteLog(L"Tray path: " + app_path);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PSECURITY_DESCRIPTOR process_security_descriptor = CreateProtectedProcessSecurityDescriptor();
    SECURITY_ATTRIBUTES process_security{};
    process_security.nLength = sizeof(process_security);
    process_security.lpSecurityDescriptor = process_security_descriptor;
    process_security.bInheritHandle = FALSE;

    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessAsUserW(
        primary_token,
        app_path.c_str(),
        command_line.data(),
        process_security_descriptor ? &process_security : nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        environment,
        GetCurrentDirectoryForModule().c_str(),
        &startup,
        &process
    );

    if (process_security_descriptor) {
        LocalFree(process_security_descriptor);
    }
    if (environment) {
        DestroyEnvironmentBlock(environment);
    }
    CloseHandle(primary_token);

    if (created) {
        WriteLog(L"Tray process started, pid=" + std::to_wstring(process.dwProcessId));
        RememberTrayProcess(process);
    } else {
        WriteLastErrorLog(L"CreateProcessAsUserW");
    }
}

void LaunchTrayForLoggedOnSessions() {
    WriteLog(L"Enumerating terminal sessions");
    CleanupStoppedTrayProcesses();

    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        WriteLastErrorLog(L"WTSEnumerateSessionsW");
        return;
    }

    for (DWORD i = 0; i < count; ++i) {
        WriteLog(
            L"Session " + std::to_wstring(sessions[i].SessionId) +
            L", state=" + std::to_wstring(static_cast<int>(sessions[i].State))
        );
        if (sessions[i].SessionId != 0 &&
            (sessions[i].State == WTSActive || sessions[i].State == WTSConnected)) {
            LaunchTrayForSession(sessions[i].SessionId);
        }
    }

    WTSFreeMemory(sessions);
}

DWORD WINAPI RpcThreadProc(void*) {
    WriteLog(L"Starting RPC server");
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr
    );
    if (status != RPC_S_OK) {
        WriteLog(L"RpcServerUseProtseqEpW failed, status=" + std::to_wstring(status));
        SetEvent(g_stop_event);
        return status;
    }

    status = RpcServerRegisterIf(ZIOVPOControl_v1_0_s_ifspec, nullptr, nullptr);
    if (status != RPC_S_OK) {
        WriteLog(L"RpcServerRegisterIf failed, status=" + std::to_wstring(status));
        SetEvent(g_stop_event);
        return status;
    }

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING) {
        WriteLog(L"RpcServerListen failed, status=" + std::to_wstring(status));
        SetEvent(g_stop_event);
        return status;
    }

    WriteLog(L"RPC server started");

    return ERROR_SUCCESS;
}

DWORD WINAPI ServiceControlHandlerEx(DWORD control, DWORD event_type, void*, void*) {
    if (control == SERVICE_CONTROL_INTERROGATE) {
        SetServiceStatus(g_status_handle, &g_status);
        return NO_ERROR;
    }

    if (control == SERVICE_CONTROL_SESSIONCHANGE) {
        if (event_type == WTS_SESSION_LOGON ||
            event_type == WTS_SESSION_UNLOCK ||
            event_type == WTS_CONSOLE_CONNECT ||
            event_type == WTS_REMOTE_CONNECT) {
            LaunchTrayForLoggedOnSessions();
        }
        return NO_ERROR;
    }

    return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandlerEx, nullptr);
    if (!g_status_handle) {
        return;
    }

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwServiceSpecificExitCode = 0;
    SetServiceState(SERVICE_START_PENDING, NO_ERROR, 3000);
    ApplyProtectedDaclToCurrentProcess();

    InitializeCriticalSection(&g_process_lock);
    InitializeCriticalSection(&g_auth_lock);
    InitializeCriticalSection(&g_av_lock);
    InitializeCriticalSection(&g_schedule_lock);
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_monitor_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop_event || !g_monitor_stop_event) {
        SetServiceState(SERVICE_STOPPED, GetLastError());
        if (g_stop_event) {
            CloseHandle(g_stop_event);
        }
        if (g_monitor_stop_event) {
            CloseHandle(g_monitor_stop_event);
        }
        DeleteCriticalSection(&g_schedule_lock);
        DeleteCriticalSection(&g_av_lock);
        DeleteCriticalSection(&g_auth_lock);
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    HANDLE rpc_thread = CreateThread(nullptr, 0, RpcThreadProc, nullptr, 0, nullptr);
    if (!rpc_thread) {
        if (g_monitor_stop_event) {
            CloseHandle(g_monitor_stop_event);
            g_monitor_stop_event = nullptr;
        }
        CloseHandle(g_stop_event);
        SetServiceState(SERVICE_STOPPED, GetLastError());
        DeleteCriticalSection(&g_schedule_lock);
        DeleteCriticalSection(&g_av_lock);
        DeleteCriticalSection(&g_auth_lock);
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    g_refresh_thread = CreateThread(nullptr, 0, RefreshThreadProc, nullptr, 0, nullptr);
    g_schedule_thread = CreateThread(nullptr, 0, ScheduleThreadProc, nullptr, 0, nullptr);
    g_monitor_thread = CreateThread(nullptr, 0, MonitorThreadProc, nullptr, 0, nullptr);

    SetServiceState(SERVICE_RUNNING);
    WriteLog(L"Service is running");
    LaunchTrayForLoggedOnSessions();

    WaitForSingleObject(g_stop_event, INFINITE);

    SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    WriteLog(L"Service is stopping");
    RpcMgmtStopServerListening(nullptr);
    WaitForSingleObject(rpc_thread, 3000);
    RpcServerUnregisterIf(ZIOVPOControl_v1_0_s_ifspec, nullptr, FALSE);
    CloseHandle(rpc_thread);
    if (g_refresh_thread) {
        WaitForSingleObject(g_refresh_thread, 3000);
        CloseHandle(g_refresh_thread);
        g_refresh_thread = nullptr;
    }
    if (g_monitor_stop_event) {
        SetEvent(g_monitor_stop_event);
    }
    if (g_schedule_thread) {
        WaitForSingleObject(g_schedule_thread, 3000);
        CloseHandle(g_schedule_thread);
        g_schedule_thread = nullptr;
    }
    if (g_monitor_thread) {
        WaitForSingleObject(g_monitor_thread, 3000);
        CloseHandle(g_monitor_thread);
        g_monitor_thread = nullptr;
    }

    TerminateTrayProcesses();
    if (g_monitor_stop_event) {
        CloseHandle(g_monitor_stop_event);
        g_monitor_stop_event = nullptr;
    }
    CloseHandle(g_stop_event);
    DeleteCriticalSection(&g_schedule_lock);
    DeleteCriticalSection(&g_av_lock);
    DeleteCriticalSection(&g_auth_lock);
    DeleteCriticalSection(&g_process_lock);

    SetServiceState(SERVICE_STOPPED);
}

int wmain() {
    SERVICE_TABLE_ENTRYW service_table[] = {
        {const_cast<LPWSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr}
    };

    if (!StartServiceCtrlDispatcherW(service_table)) {
        return static_cast<int>(GetLastError());
    }

    return 0;
}

extern "C" void StopService() {
    if (g_stop_event) {
        SetEvent(g_stop_event);
    }
}

extern "C" long GetCurrentUser(long* authenticated, wchar_t** login) {
    if (!authenticated || !login) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_auth_lock);
    *authenticated = g_auth.authenticated ? 1 : 0;
    *login = RpcCopyString(g_auth.authenticated ? g_auth.login : L"");
    LeaveCriticalSection(&g_auth_lock);
    return *login ? 0 : ERROR_OUTOFMEMORY;
}

extern "C" long Login(const wchar_t* login, const wchar_t* password, wchar_t** errorMessage) {
    if (!login || !password || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring error;
    long result = AuthenticateUser(login, password, error);
    *errorMessage = RpcCopyString(error);
    return result;
}

extern "C" long Logout() {
    ClearAuthState();
    return 0;
}

extern "C" long GetLicenseStatus(long* hasLicense, wchar_t** expiresAt, wchar_t** errorMessage) {
    if (!hasLicense || !expiresAt || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring error;
    long result = QueryLicenseStatus(error);

    EnterCriticalSection(&g_auth_lock);
    *hasLicense = g_auth.hasLicense ? 1 : 0;
    *expiresAt = RpcCopyString(g_auth.licenseExpiresAt);
    LeaveCriticalSection(&g_auth_lock);
    *errorMessage = RpcCopyString(error);

    if (!*expiresAt || !*errorMessage) {
        return ERROR_OUTOFMEMORY;
    }
    return result;
}

extern "C" long ActivateProduct(const wchar_t* activationCode, wchar_t** errorMessage) {
    if (!activationCode || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring error;
    long result = ActivateLicense(activationCode, error);
    *errorMessage = RpcCopyString(error);
    return *errorMessage ? result : ERROR_OUTOFMEMORY;
}

extern "C" long AntivirusPing(wchar_t** errorMessage) {
    if (!errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    bool hasLicense = false;
    EnterCriticalSection(&g_auth_lock);
    hasLicense = g_auth.hasLicense;
    LeaveCriticalSection(&g_auth_lock);

    if (!hasLicense) {
        *errorMessage = RpcCopyString(L"License ticket is missing");
        return ERROR_NOT_READY;
    }

    *errorMessage = RpcCopyString(L"");
    return *errorMessage ? 0 : ERROR_OUTOFMEMORY;
}

extern "C" long GetAvDatabaseInfo(wchar_t** releaseDate, long* recordCount, wchar_t** errorMessage) {
    if (!releaseDate || !recordCount || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring error;
    long ready = EnsureAvReady(error);
    EnterCriticalSection(&g_av_lock);
    std::wstring date = g_av_database.release_date;
    long count = static_cast<long>(GetAvRecordCountUnlocked());
    LeaveCriticalSection(&g_av_lock);

    *releaseDate = RpcCopyString(date);
    *recordCount = count;
    *errorMessage = RpcCopyString(error);
    if (!*releaseDate || !*errorMessage) {
        return ERROR_OUTOFMEMORY;
    }
    return ready;
}

extern "C" long ScanFile(const wchar_t* path, wchar_t** result, wchar_t** errorMessage) {
    if (!path || !result || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    bool infected = false;
    std::wstring detection;
    std::wstring error;
    long code = ScanSingleFile(path, infected, detection, error);
    std::wstring report;
    if (code == 0) {
        report = infected
            ? L"INFECTED: " + std::wstring(path) + L" (" + detection + L")"
            : L"CLEAN: " + std::wstring(path);
    }

    *result = RpcCopyString(report);
    *errorMessage = RpcCopyString(error);
    return *result && *errorMessage ? code : ERROR_OUTOFMEMORY;
}

extern "C" long ScanDirectory(const wchar_t* path, wchar_t** result, wchar_t** errorMessage) {
    if (!path || !result || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring report;
    std::wstring error;
    long code = ScanPathDirectory(path, report, error);
    *result = RpcCopyString(report);
    *errorMessage = RpcCopyString(error);
    return *result && *errorMessage ? code : ERROR_OUTOFMEMORY;
}

extern "C" long ScanFixedDrives(wchar_t** result, wchar_t** errorMessage) {
    if (!result || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring report;
    std::wstring error;
    long code = ScanAllFixedDrivesInternal(report, error);
    *result = RpcCopyString(report);
    *errorMessage = RpcCopyString(error);
    return *result && *errorMessage ? code : ERROR_OUTOFMEMORY;
}

extern "C" long ConfigureScheduleScan(long intervalMinutes, const wchar_t* path, wchar_t** errorMessage) {
    if (!path || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }
    if (intervalMinutes <= 0) {
        *errorMessage = RpcCopyString(L"Interval must be positive");
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_schedule_lock);
    g_schedule.enabled = true;
    g_schedule.interval_minutes = intervalMinutes;
    g_schedule.path = path;
    g_schedule.next_scan_tick = GetTickCount64() + static_cast<ULONGLONG>(intervalMinutes) * 60ULL * 1000ULL;
    g_schedule.last_result.clear();
    LeaveCriticalSection(&g_schedule_lock);

    *errorMessage = RpcCopyString(L"");
    return *errorMessage ? 0 : ERROR_OUTOFMEMORY;
}

extern "C" long GetScheduledScanResult(wchar_t** result, wchar_t** errorMessage) {
    if (!result || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring lastResult;
    EnterCriticalSection(&g_schedule_lock);
    lastResult = g_schedule.last_result;
    LeaveCriticalSection(&g_schedule_lock);

    *result = RpcCopyString(lastResult);
    *errorMessage = RpcCopyString(L"");
    return *result && *errorMessage ? 0 : ERROR_OUTOFMEMORY;
}

extern "C" long ConfigureDirectoryMonitoring(const wchar_t* path, wchar_t** errorMessage) {
    if (!path || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_schedule_lock);
    g_monitor_path = path;
    g_monitor_last_result = L"Directory monitoring configured for: " + g_monitor_path;
    LeaveCriticalSection(&g_schedule_lock);

    *errorMessage = RpcCopyString(L"");
    return *errorMessage ? 0 : ERROR_OUTOFMEMORY;
}

extern "C" long GetDirectoryMonitoringResult(wchar_t** result, wchar_t** errorMessage) {
    if (!result || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring lastResult;
    EnterCriticalSection(&g_schedule_lock);
    lastResult = g_monitor_last_result;
    LeaveCriticalSection(&g_schedule_lock);

    *result = RpcCopyString(lastResult);
    *errorMessage = RpcCopyString(L"");
    return *result && *errorMessage ? 0 : ERROR_OUTOFMEMORY;
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    free(pointer);
}
