// Windows version of the platform layer.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
// order matters
#include <shlobj.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <wintrust.h>

#include <vector>

#include "hem_guard/platform.hpp"

namespace hem::guard {

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

// WinVerifyTrust wants a window handle; "no window" is spelled INVALID_HANDLE_VALUE.
#define kNoWindow reinterpret_cast<HWND>(INVALID_HANDLE_VALUE)

// Newer catalog calls are loaded by name so older headers / systems do not break the build.
using AcquireCtx2Fn = BOOL(WINAPI*)(HCATADMIN*, const GUID*, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);
using CalcHash2Fn = BOOL(WINAPI*)(HCATADMIN, HANDLE, DWORD*, BYTE*, DWORD);

std::wstring hash_to_tag(const std::vector<BYTE>& h) {
    static const wchar_t* d = L"0123456789ABCDEF";
    std::wstring t;
    for (BYTE b : h) {
        t.push_back(d[b >> 4]);
        t.push_back(d[b & 15]);
    }
    return t;
}

bool verify_embedded(const std::wstring& path, LONG& result) {
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof fi;
    fi.pcwszFilePath = path.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof wd;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;  // never reach out to the network
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    result = WinVerifyTrust(kNoWindow, &action, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(kNoWindow, &action, &wd);
    return result == ERROR_SUCCESS;
}

bool verify_via_catalog(const std::wstring& path) {
    HMODULE wt = LoadLibraryW(L"wintrust.dll");
    if (!wt) return false;
    auto acquire2 = reinterpret_cast<AcquireCtx2Fn>(reinterpret_cast<void*>(GetProcAddress(wt, "CryptCATAdminAcquireContext2")));
    auto calc2 = reinterpret_cast<CalcHash2Fn>(reinterpret_cast<void*>(GetProcAddress(wt, "CryptCATAdminCalcHashFromFileHandle2")));

    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    bool ok = false;
    const wchar_t* algs[2] = {L"SHA256", nullptr};  // modern catalogs use SHA-256, old ones SHA-1
    for (int round = 0; round < 2 && !ok; ++round) {
        HCATADMIN adm = nullptr;
        if (acquire2) {
            if (!acquire2(&adm, nullptr, algs[round], nullptr, 0)) continue;
        } else {
            if (round > 0 || !CryptCATAdminAcquireContext(&adm, nullptr, 0)) continue;
        }
        DWORD hash_len = 0;
        std::vector<BYTE> hash;
        bool hashed = false;
        if (calc2) {
            calc2(adm, h, &hash_len, nullptr, 0);
            if (hash_len > 0) {
                hash.resize(hash_len);
                hashed = calc2(adm, h, &hash_len, hash.data(), 0) != FALSE;
            }
        } else {
            CryptCATAdminCalcHashFromFileHandle(h, &hash_len, nullptr, 0);
            if (hash_len > 0) {
                hash.resize(hash_len);
                hashed = CryptCATAdminCalcHashFromFileHandle(h, &hash_len, hash.data(), 0) != FALSE;
            }
        }
        if (hashed) {
            hash.resize(hash_len);
            HCATINFO cat = CryptCATAdminEnumCatalogFromHash(adm, hash.data(), hash_len, 0, nullptr);
            if (cat) {
                CATALOG_INFO ci{};
                ci.cbStruct = sizeof ci;
                if (CryptCATCatalogInfoFromContext(cat, &ci, 0)) {
                    const std::wstring tag = hash_to_tag(hash);
                    WINTRUST_CATALOG_INFO wci{};
                    wci.cbStruct = sizeof wci;
                    wci.pcwszCatalogFilePath = ci.wszCatalogFile;
                    wci.pcwszMemberTag = tag.c_str();
                    wci.pcwszMemberFilePath = path.c_str();
                    wci.hMemberFile = h;
                    wci.pbCalculatedFileHash = hash.data();
                    wci.cbCalculatedFileHash = hash_len;
                    wci.hCatAdmin = adm;
                    WINTRUST_DATA wd{};
                    wd.cbStruct = sizeof wd;
                    wd.dwUIChoice = WTD_UI_NONE;
                    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                    wd.pCatalog = &wci;
                    wd.dwStateAction = WTD_STATEACTION_VERIFY;
                    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
                    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    const LONG r = WinVerifyTrust(kNoWindow, &action, &wd);
                    wd.dwStateAction = WTD_STATEACTION_CLOSE;
                    WinVerifyTrust(kNoWindow, &action, &wd);
                    ok = (r == ERROR_SUCCESS);
                }
                CryptCATAdminReleaseCatalogContext(adm, cat, 0);
            }
        }
        CryptCATAdminReleaseContext(adm, 0);
    }
    CloseHandle(h);
    return ok;
}

}  // namespace

const char* to_string(SignState s) {
    switch (s) {
        case SignState::Signed: return "signed";
        case SignState::Unsigned: return "unsigned";
        default: return "unknown";
    }
}

bool is_reparse_or_symlink(const fs::path& p) {
    const DWORD a = GetFileAttributesW(p.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return false;
    return (a & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

SignState check_signature(const fs::path& p) {
    std::error_code ec;
    if (!fs::is_regular_file(p, ec)) return SignState::Unknown;
    const std::wstring wp = p.wstring();
    LONG r = 0;
    if (verify_embedded(wp, r)) return SignState::Signed;
    if (verify_via_catalog(wp)) return SignState::Signed;
    return SignState::Unsigned;  // no valid signature found
}

double process_cpu_seconds() {
    FILETIME c, e, k, u;
    if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) return 0.0;
    auto ticks = [](const FILETIME& f) {
        return double((static_cast<unsigned long long>(f.dwHighDateTime) << 32) | f.dwLowDateTime) * 100e-9;
    };
    return ticks(k) + ticks(u);
}

std::optional<std::string> env_var(const char* name) {
    const std::wstring wn = widen(name);
    const DWORD n = GetEnvironmentVariableW(wn.c_str(), nullptr, 0);
    if (n == 0) return std::nullopt;
    std::wstring v(n, L'\0');
    const DWORD got = GetEnvironmentVariableW(wn.c_str(), v.data(), n);
    v.resize(got);
    if (v.empty()) return std::nullopt;
    return narrow(v);
}

namespace {
fs::path folder(const KNOWNFOLDERID& id) {
    PWSTR out = nullptr;
    if (SHGetKnownFolderPath(id, 0, nullptr, &out) != S_OK || !out) return {};
    fs::path p(out);
    CoTaskMemFree(out);
    return p;
}
}  // namespace

KnownFolders known_folders() {
    KnownFolders k;
    k.profile = folder(FOLDERID_Profile);
    k.documents = folder(FOLDERID_Documents);
    k.desktop = folder(FOLDERID_Desktop);
    k.pictures = folder(FOLDERID_Pictures);
    k.music = folder(FOLDERID_Music);
    k.videos = folder(FOLDERID_Videos);
    k.downloads = folder(FOLDERID_Downloads);
    return k;
}

int run_process(const std::vector<std::string>& args, std::string& output) {
    output.clear();
    if (args.empty()) return -1;
    std::string cmd;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (i) cmd.push_back(' ');
        cmd += quote_windows_arg(args[i]);
    }
    std::wstring wcmd = widen(cmd);

    SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    const BOOL ok = CreateProcessW(nullptr, wcmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!ok) {
        CloseHandle(rd);
        return -1;
    }
    char buf[4096];
    DWORD got = 0;
    while (ReadFile(rd, buf, sizeof buf, &got, nullptr) && got > 0) output.append(buf, got);
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, 60000);
    DWORD code = 0;
    if (!GetExitCodeProcess(pi.hProcess, &code)) code = static_cast<DWORD>(-1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(code);
}

std::string current_user_sid() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return {};
    DWORD need = 0;
    GetTokenInformation(tok, TokenUser, nullptr, 0, &need);
    std::string out;
    if (need > 0) {
        std::vector<unsigned char> buf(need);
        if (GetTokenInformation(tok, TokenUser, buf.data(), need, &need)) {
            LPWSTR w = nullptr;
            if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &w) && w) {
                out = to_u8(fs::path(std::wstring(w)));
                LocalFree(w);
            }
        }
    }
    CloseHandle(tok);
    return out;
}

bool is_windows() { return true; }

}  // namespace hem::guard

#endif
