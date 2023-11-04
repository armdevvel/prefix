#include "paths.h"

#include <windows.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <psapi.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
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
    std::size_t str_len = strlen(out.data());
    if(str_len < out_len) out.resize(str_len);
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

void ToDirname(std::string& modpath) {
    std::size_t dirseppos = modpath.rfind('\\');
    if(std::string::npos != dirseppos) { // true
        modpath.resize(dirseppos);
    }
}

bool ToDriveLtr_ViaShortPath(std::string& modpath) {
    // we may want to ask whether AreShortNamesEnabled beforehand...
     std::string path8_3 = RequestVarLen([&](char* buf, std::size_t len) {
        return (std::size_t) GetShortPathNameA(modpath.c_str(), buf, len);
    });
    if(path8_3.size()) {
         if(std::string::npos == path8_3.find('~')) {
            //_PREFIX_LOG("path8_3=%s, use as is", path8_3.c_str());
            modpath = path8_3; // this works
        } else {
            modpath = RequestVarLen([&](char* buf, std::size_t len) { // works too
                return (std::size_t) GetLongPathNameA(path8_3.c_str(), buf, len);
            });
            //_PREFIX_LOG("lngpath=%s", modpath.c_str());
        }
        return true;
    }
    return false;
}

bool ToDriveLtr_ViaFinalPath(std::string& modpath) {
    // https://stackoverflow.com/questions/48320430/convert-from-windows-nt-device-path-to-drive-letter-path
    std::string glbpath = "\\\\?\\GLOBALROOT"; glbpath += modpath;
    HANDLE mod = CreateFileA(glbpath.c_str(), GENERIC_READ, FILE_SHARE_VALID_FLAGS, NULL, OPEN_EXISTING, 0, NULL);
    if(INVALID_HANDLE_VALUE != mod) { // method 3 works
        std::string finpath = RequestVarLen([mod](char* buf, std::size_t len) {
            return (std::size_t) GetFinalPathNameByHandleA(mod, buf, len, VOLUME_NAME_DOS|FILE_NAME_NORMALIZED);
        });
        CloseHandle(mod);
        if(strncmp(finpath.c_str(), "\\\\?\\", 4)) {
            modpath = finpath;
        } else {
            modpath.assign(finpath.begin() + 4, finpath.end());
        }
        //_PREFIX_LOG("finpath=%s", modpath.c_str());
        return true;
    }
    return false;
}

bool ToDriveLtr_ViaDrivePath(std::string& modpath) {
    std::string dospath = "A:";
    char* drv_str = &dospath[0];
    for(char drv = 'A'; drv <= 'Z'; ++drv) {
        *drv_str = drv;
        std::string volpath = RequestVarLen([drv_str](char* buf, std::size_t len) {
            std::size_t char_count = QueryDosDeviceA(drv_str, buf, len);
            return char_count ? char_count : (GetLastError() == ERROR_INSUFFICIENT_BUFFER) ? (2*len+11) : 0;
        });
        //_PREFIX_LOG("volpath[%lu]=%s dospath=%s", volpath.size(), volpath.c_str(), dospath.c_str());
        if(volpath.size() && !strncasecmp(modpath.data(), volpath.data(), volpath.size())) {
            modpath = dospath + std::string(modpath.begin() + volpath.size(), modpath.end());
            //_PREFIX_LOG("dospath=%s", modpath.c_str());
            return true;
        }
    }
    return false;
}

bool ToDriveLtr(std::string& modpath) {
    assert(modpath.size());
    // convert volume to drv:
    return (std::string::npos != modpath.find(':'))
        || ToDriveLtr_ViaShortPath(modpath)
        || ToDriveLtr_ViaFinalPath(modpath)
        || ToDriveLtr_ViaDrivePath(modpath);
}

/* end of utilities -- the business logic begins */

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

static bool canary_failed = false; // tried to locate the sysroot but found no

// Now the hell breaks loose. The following options affect sysroot:
// fixpre_config_options__tmp_dir_as_sysroot (emergency, overrides all)
// fixpre_config_options__env_var_as_sysroot (overrides all but tmp_dir)
// fix
// fixpre_config_options__app_dir_as_sysroot (overrides canary)
// fixpre_config_options__app_dir_as_lib_dir (a different canary)
std::string Sysroot(int mods, enum fixpre_config_options options, GDP get_dep)
{
    _PREFIX_LOG("Searching for sysroot, options=%08x", options);
     if(fixpre_config_options__tmp_dir_as_sysroot & options) {
        _PREFIX_LOG("Sysroot set to the temporary file directory");
        return get_dep(mods | fixpre_known_path__tmp_dir);
    }
    if(fixpre_config_options__env_var_as_sysroot & options) {
        auto envvar = ExpandEnvvars("%" _PREFIX_DISTRO_NAME "%");
        if(envvar.size() && PathIsDirectoryA(envvar.c_str())) {
            _PREFIX_LOG("Sysroot overridden with %%" _PREFIX_DISTRO_NAME "%%: %s",
                envvar.c_str());
            return envvar;
        }
    }
    if(fixpre_config_options__profile_as_sysroot & options) {
        // tempting to |=fixpre_path_modifiers__profile_dir, but let the caller decide
        return get_dep(mods | fixpre_known_path__datadir) + _PREFIX_DISTRO_NAME;
    }
    const int use_main_mask = fixpre_config_options__app_dir_as_sysroot
                            | fixpre_config_options__app_dir_as_lib_dir;
    const bool use_main_module = use_main_mask & options;
    std::string apppath = RequestVarLen([](char* buf, std::size_t len) {
            return GetModuleFileNameA(NULL, buf, len);
        });
    ToDriveLtr(apppath);
    // fixpre_config_options__app_dir_as_sysroot means "do not resolve sysroot"
    if(fixpre_config_options__app_dir_as_sysroot & options) {
        _PREFIX_LOG("Sysroot set to the app directory (request): %s", apppath.c_str());
        ToDirname(apppath);
        return apppath;
    }
    std::string modpath;
    if(use_main_module) {
        modpath = apppath;
    } else {
        modpath = RequestVarLen([](char* buf, std::size_t len) {
            return (std::size_t) GetMappedFileNameA(GetCurrentProcess(), (void*)&Sysroot, buf, len);
        });
        ToDriveLtr(modpath);
    }
    // actually resolve sysroot, modifying modpath on success
    std::string coalmine = "\\" _SUFFIX_PATH_PRE;
    for(char& c : coalmine) { if(c=='/') c='\\'; } // inline 'tr'
    std::size_t minepos = modpath.rfind(coalmine);
    if(std::string::npos != minepos) {
        modpath.resize(minepos + 1u);
        _PREFIX_LOG("Sysroot found the vanilla way: %s", modpath.c_str());
        return modpath;
    } else {
        canary_failed = true;
        // remove basename
        ToDirname(apppath);
        _PREFIX_LOG("Sysroot set to the app directory (despair): %s", apppath.c_str());
        return apppath;
    }
}

// The following options have no general effect on sysroot but affect etcroot:
// fixpre_config_options__profile_as_etcroot (only applied in Cfgroot())
// fixpre_config_options__profile_as_etchome (only applied in Cfgroot())
std::string Cfgroot(int mods, enum fixpre_config_options options, GDP get_dep)
{
    const bool transient = fixpre_config_options__tmp_dir_as_sysroot & options;
    const bool bare_home = fixpre_config_options__profile_as_etchome & options;
    const bool want_home = fixpre_config_options__profile_as_etcroot & options;
    if(bare_home && !transient) {
        auto rv = get_dep(mods | fixpre_known_path__homedir);
        _PREFIX_LOG("cfgroot=homedir:%s", rv.c_str());
        return rv;
    }
    if(want_home || canary_failed) {
        // same as Sysroot() under `fixpre_config_options__profile_as_sysroot`:
        auto rv = get_dep(mods | fixpre_known_path__datadir) + _PREFIX_DISTRO_NAME;
        _PREFIX_LOG("cfgroot=datadir:%s", rv.c_str());
        return rv;
    } else {
        auto rv = get_dep(mods | fixpre_known_path__sysroot);
        _PREFIX_LOG("cfgroot=sysroot:%s", rv.c_str());
        return rv;
    }
}

// The following options affect post-lookup behavior:
// fixpre_config_options__tuning_noninvasive (does not affect lookup)

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
    const fixpre_known_path kind = _PREFIX_ENUM_KNOWN_PATH(path_kind);
    const int mods = path_kind & _PREFIX_PATH_TUNING_MASK;

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
            return Sysroot(mods, options, get_dep);
        case fixpre_known_path__etcroot:
            return Cfgroot(mods, options, get_dep);

        /* lookup paths */
        case fixpre_known_path__defpath: return "TODO _PATH_DEFPATH";  /* userspace */
        case fixpre_known_path__stdpath: return "TODO _PATH_STDPATH";  /* servicespace */

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
