#include "paths.h"

#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>

#include <sys/stat.h>
#include <sys/types.h>
#if __has_include(<fatctl/mode.h>)
#include <fatctl/mode.h>
#endif

#include <cstdint>
#include <algorithm>

#include "def.h"
#include "dbg.h"

extern "C"
{

int fixpre_file_type(int path_kind) {
    const enum fixpre_known_path kind = _PREFIX_ENUM_KNOWN_PATH(path_kind);
    if(fixpre_known_path__c_shell == kind) {
        return S_IFREG;
    }
    if(fixpre_path_families__devices == (kind & _PREFIX_PATH_FAMILY_MASK)) {
        return S_IFCHR;
    } else {
        return S_IFDIR;
    }
}

const char* fixpre_explain(int path_kind) {
    const enum fixpre_known_path kind = _PREFIX_ENUM_KNOWN_PATH(path_kind);
    switch(kind) {
        case fixpre_known_path__windows: return "Windows installation dir";
        case fixpre_known_path__sys_dir: return "Windows system directory";
        case fixpre_known_path__c_shell: return "Command line shell (%ComSpec%)";
        case fixpre_known_path__dot_net: return ".NET framework root";
        case fixpre_known_path__homedir: return "User home directory (%USERPROFILE% or %PUBLIC%)";
        case fixpre_known_path__datadir: return "Application data directory (local)";
        case fixpre_known_path__roaming: return "Application data directory (roaming)";
        case fixpre_known_path__tmp_dir: return "Temporary file directory";
        case fixpre_known_path__sysroot: return _PREFIX_DISTRO_NAME " distro root";
        case fixpre_known_path__etcroot: return _PREFIX_DISTRO_NAME " configuration root";
        case fixpre_known_path__defpath: return "Default %PATH% for userspace programs";
        case fixpre_known_path__stdpath: return "Default %PATH% for background services";
        case fixpre_known_path__devnull: return "The black hole device";
        case fixpre_known_path__tty:     return "The console (standard I/O)";
        case fixpre_known_path__pipe_fs: return "The named pipe pseudo-file-system root";
        default: return nullptr;
    }
}

} // extern "C"s

namespace fixpre {
namespace detail {

namespace {

/* No Unicode support. Paths are ASCII. */

using TryRequestMaxLen = std::function<bool(char*)>;
using TryRequestVarLen = std::function<std::size_t(char*, std::size_t)>;

std::string RequestMaxLen(TryRequestMaxLen try_request_maxlen) {
    std::string out(MAX_PATH, '\0');
    if(try_request_maxlen(&out[0])) {
        std::size_t where = out.find('\0');
        if(where != std::string::npos) {
            out.resize(where);
        }
    } else out.clear();
    return out;
}

std::string RequestVarLen(TryRequestVarLen try_request_varlen) {
    std::size_t def_len = MAX_PATH;
    std::string out(def_len, '\0');
    std::size_t out_len = try_request_varlen(&out[0], out.size());
    out.resize(out_len, '\0');
    if(out_len > def_len) {
        // request complete data
        try_request_varlen(&out[0], out.size());
    }
    return out;
}

std::string RequestSpecial(int csidl) {
    return RequestMaxLen([csidl](char* buf) {
        return ERROR_SUCCESS == SHGetFolderPathA(
            NULL /*hwnd */, csidl,
            NULL /* acc_token */,
            SHGFP_TYPE_CURRENT, buf
        );
    });
}

std::string ExpandEnvvars(const char * percent_str) {
    return RequestVarLen([percent_str](char* buffer, std::size_t limit) {
        return ExpandEnvironmentStringsA(percent_str, buffer, limit);
    });
}

std::string Dotnet(const std::string& win_dir) {
    HKEY key;
    DWORD err = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\.NETFramework", 0, KEY_READ, &key);
    if(ERROR_SUCCESS == err) {
        std::string out = RequestVarLen([key](char* buf, std::size_t buflen) {
            DWORD len = buflen; // int-to-long
            DWORD err = RegGetValueA(key, NULL, "InstallRoot", RRF_RT_REG_SZ, NULL, buf, &len);
            if(ERROR_SUCCESS == err) {
                return (std::size_t)len;
            } else {
                _PREFIX_LOG("RegGetValueA: err=%lu", err);
                return 0u;
            }
        });
        RegCloseKey(key);
        return out;
    } else {
        _PREFIX_LOG("RegOpenKeyExA: err=%lu", err);
    }
    return win_dir + "Microsoft.NET/Framework";
}

std::string Sysroot(enum fixpre_config_options options, GDP get_dep)
{
    // hell breaks loose
    if(fixpre_config_options__profile_as_etchome & options) {}
    //
    // TODO
    return "TODO " _PREFIX_DISTRO_NAME;
}

std::string Cfgroot(enum fixpre_config_options options, GDP get_dep)
{
    if(fixpre_config_options__profile_as_etchome & options) {
        return get_dep(fixpre_known_path__homedir);
    } else {
        return get_dep(fixpre_known_path__sysroot);
    }
}

} // anonymous

/**
 * precondition: called in ascending order
 * postconditions: none, 'gps.cpp' undoes all format liberties
 */
__attribute__((visibility("hidden")))
std::string OSPathLookup(int path_kind, enum fixpre_config_options options, GDP get_dep) {
    bool is_userdir = path_kind & fixpre_path_modifiers__profile_dir;
    bool is_cfg_dir = path_kind & fixpre_path_modifiers__cfgfile_dir;
    // MOREINFO options MAY affect the above flags; if not, make const

    const bool is_separated_path = _PREFIX_PATH_IS_PATHLIST(path_kind);
    const fixpre_known_path kind = Known(path_kind & ~_PREFIX_PATH_TUNING_MASK);

    // See explanation in:
    // http://cvsweb.netbsd.org/bsdweb.cgi/src/include/paths.h.diff?r1=1.10&r2=1.11
    // ^^^ _PATH_DEFPATH is for the user by default; _PATH_STDPATH is for services
    switch(kind) {
        /* Windows paths */
        case fixpre_known_path__windows: // same as %Windir%
            return RequestVarLen(is_userdir ? &GetWindowsDirectoryA : &GetSystemWindowsDirectoryA);
                                         // choice of system function matters on multi-user systems
        case fixpre_known_path__sys_dir:
            return RequestVarLen(&GetSystemDirectoryA);
        case fixpre_known_path__c_shell: // /* %ComSpec% */
            return ExpandEnvvars("%ComSpec%");
        case fixpre_known_path__dot_net: // e.g. "C:\Windows\Microsoft.NET\Framework\"
            return (path_kind == kind) ? Dotnet(get_dep(fixpre_known_path__windows)) : get_dep(kind);
        case fixpre_known_path__datadir: // /* AppData\Local or ProgramData */
            return RequestSpecial(is_userdir ? CSIDL_LOCAL_APPDATA : CSIDL_COMMON_APPDATA);
        case fixpre_known_path__roaming: // /* AppData\Roaming folder, i.e. %APPDATA% */
            return is_userdir ? RequestSpecial(CSIDL_APPDATA) : ""; // no user, no roaming
        case fixpre_known_path__homedir: // /* profile ? %USERPROFILE% : %PUBLIC% */
            return is_userdir ? RequestSpecial(CSIDL_PROFILE) : ExpandEnvvars("%PUBLIC%");
        case fixpre_known_path__tmp_dir: // /* %TEMP%, %TMP% */
        {
            auto temp = ExpandEnvvars("%TEMP%");
            if(temp.empty()) temp = ExpandEnvvars("%TMP%");
            if(temp.empty() && is_userdir) { // okay then...
                // ... how about that?
                temp = RequestSpecial(CSIDL_INTERNET_CACHE);
            }
            if(temp.empty()) temp = ".";
            return temp;
        }

        /* distro paths */
        case fixpre_known_path__sysroot:
            return Sysroot(options, get_dep);
        case fixpre_known_path__etcroot:
            return Cfgroot(options, get_dep);

        /* lookup paths */
        case fixpre_known_path__defpath: return "TODO _PATH_STDPATH";  /* interactivespace */
        case fixpre_known_path__stdpath: return "TODO _PATH_STDPATH";  /* "servicespace" */

        /* device paths */
        case fixpre_known_path__devnull: return "nul";
        case fixpre_known_path__tty:     return "con";

        /* non-fs paths */
        case fixpre_known_path__pipe_fs: return "//./pipe/";
        default: return {};
    }
}

__attribute__((visibility("hidden")))
void SweetHome(const std::string& home) {
    if(home.size() && !GetEnvironmentVariableA("HOME", nullptr, 0) && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        const char* c_home = home.c_str();
        _PREFIX_LOG("set HOME=%s", c_home);
        SetEnvironmentVariableA("HOME", c_home);
    }
}

} // namespace detail
} // namespace fixpre
