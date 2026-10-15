/*
 * WARP SNI Patcher - Unified CLI and Entry Point
 * English-only command-line interface with smart GUI auto-launch.
 */

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "patcher.h"
#include "service.h"
#include "gui/gui.h"
#ifdef WARP_HAS_CAPSTONE
#include "../resources/capstone_notices.h"
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <shellapi.h>
#else
#include <unistd.h>
#endif

namespace warp {

static void Usage() {
    std::puts(
        "WARP SNI Patcher\n\n"
        "Usage: warp-sni-patcher <inspect|patch|restore> [options]\n\n"
        "  --target FILE      Service executable (default: installed WARP)\n"
        "  --sni HOST         MASQUE hostname (default: speed.cloudflare.com)\n"
        "  --reg-api HOST     API hostname (default: api.devices.cloudflare.com)\n"
        "  --gui              Launch graphical interface\n"
#ifdef WARP_HAS_CAPSTONE
        "  --licenses         Show bundled dependency notices\n"
#endif
        "  --help             Show this help\n\n"
        "Run an elevated terminal to patch/restore installed WARP.\n"
        "The original binary is saved as <target>.bak. Patching changes its signature."
    );
}

int RunCli(int argc, char** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    if (argc < 2 || std::strcmp(argv[1], "--help") == 0 || std::strcmp(argv[1], "-h") == 0) {
        Usage();
        return 0;
    }

    std::string action = argv[1];
#ifdef WARP_HAS_CAPSTONE
    if (action == "--licenses") {
        std::puts(kCapstoneNotices);
        return 0;
    }
#endif
    if (action != "inspect" && action != "patch" && action != "restore") {
        std::fprintf(stderr, "Expected inspect, patch, or restore. See --help.\n");
        return 2;
    }

    PatchOptions options;
    bool has_sni = false;
    bool has_reg_api = false;

    for (int i = 2; i < argc; ++i) {
        std::string opt = argv[i];
        std::string val;
        if (opt == "--target" || opt == "--sni" || opt == "--reg-api") {
            if (++i >= argc || argv[i][0] == '\0' || std::strncmp(argv[i], "--", 2) == 0) {
                std::fprintf(stderr, "Missing value for %s\n", opt.c_str());
                return 2;
            }
            val = argv[i];
        }

        if (opt == "--target") options.target_path = val;
        else if (opt == "--sni") { options.masque_host = val; has_sni = true; }
        else if (opt == "--reg-api") { options.reg_api_host = val; has_reg_api = true; }
        else if (opt == "--help" || opt == "-h") { Usage(); return 0; }
        else { std::fprintf(stderr, "Unknown option: %s\n", opt.c_str()); return 2; }
    }

    if (action != "patch" && (has_sni || has_reg_api)) {
        std::fprintf(stderr, "Hostname options apply only to patch.\n");
        return 2;
    }

    if (action == "inspect") {
        return RunInspect(options.target_path) ? 0 : 1;
    }

    if (action == "patch" && !has_sni && !has_reg_api) {
        options.masque_host = DEFAULT_SNI;
        options.reg_api_host = DEFAULT_REG_SNI;
    }
    return RunOperation(options, action == "restore") ? 0 : 1;

}

} // namespace warp

#if defined(_WIN32) && !defined(WARP_NO_GUI)
static void SetupConsoleOrPipes() {
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    BOOL hasPipes = (hStdOut != NULL && hStdOut != INVALID_HANDLE_VALUE && GetFileType(hStdOut) != FILE_TYPE_UNKNOWN);
    if (!hasPipes) {
        if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            HANDLE hConOut = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                                         NULL, OPEN_EXISTING, 0, NULL);
            if (hConOut != INVALID_HANDLE_VALUE) {
                SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
                SetStdHandle(STD_ERROR_HANDLE, hConOut);
            }
            HANDLE hConIn = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                         NULL, OPEN_EXISTING, 0, NULL);
            if (hConIn != INVALID_HANDLE_VALUE) SetStdHandle(STD_INPUT_HANDLE, hConIn);
        }
    }
    hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdOut != NULL && hStdOut != INVALID_HANDLE_VALUE) {
        int fd = _open_osfhandle((intptr_t)hStdOut, _O_TEXT);
        if (fd != -1) {
            FILE* fp = _fdopen(fd, "w");
            if (fp) { *stdout = *fp; setvbuf(stdout, NULL, _IONBF, 0); }
        }
    }
    HANDLE hStdErr = GetStdHandle(STD_ERROR_HANDLE);
    if (hStdErr != NULL && hStdErr != INVALID_HANDLE_VALUE) {
        int fd = _open_osfhandle((intptr_t)hStdErr, _O_TEXT);
        if (fd != -1) {
            FILE* fp = _fdopen(fd, "w");
            if (fp) { *stderr = *fp; setvbuf(stderr, NULL, _IONBF, 0); }
        }
    }
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdIn != NULL && hStdIn != INVALID_HANDLE_VALUE) {
        int fd = _open_osfhandle((intptr_t)hStdIn, _O_TEXT);
        if (fd != -1) {
            FILE* fp = _fdopen(fd, "r");
            if (fp) *stdin = *fp;
        }
    }
}

static BOOL IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

static int PatcherMain(HINSTANCE hInstance, int nCmdShow, int argc, char** argv) {
    bool want_gui = false;
    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "--gui") == 0 || _stricmp(argv[i], "-gui") == 0) {
            want_gui = true;
            break;
        }
    }

    if (!want_gui) {
        if (argc <= 1) {
            bool has_console = AttachConsole(ATTACH_PARENT_PROCESS);
            if (!has_console) want_gui = true;
        }
    }

    if (want_gui) {
        std::string target = DEFAULT_TARGET_PATH;
        for (int i = 1; i + 1 < argc; ++i)
            if (std::strcmp(argv[i], "--target") == 0) target = argv[++i];
        if (warp::IsInstalledTarget(target) && !IsRunAsAdmin()) {
            WCHAR szExe[MAX_PATH];
            if (GetModuleFileNameW(NULL, szExe, MAX_PATH)) {
                SHELLEXECUTEINFOW sei;
                std::memset(&sei, 0, sizeof(sei));
                sei.cbSize = sizeof(sei);
                sei.lpVerb = L"runas";
                sei.lpFile = szExe;
                // Preserve target, hostnames and language across the normal UAC prompt.
                const wchar_t* args = GetCommandLineW();
                if (*args == L'"') {
                    ++args;
                    while (*args && *args != L'"') ++args;
                    if (*args) ++args;
                } else {
                    while (*args && *args != L' ' && *args != L'\t') ++args;
                }
                sei.lpParameters = argc > 1 ? args : L"--gui";
                sei.nShow = SW_SHOWNORMAL;
                if (ShellExecuteExW(&sei)) return 0;
            }
            return 1;
        }
        return RunGui(hInstance ? hInstance : GetModuleHandle(NULL), nCmdShow, argc, argv);
    }

    SetupConsoleOrPipes();
    return warp::RunCli(argc, argv);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance; (void)lpCmdLine;
    return PatcherMain(hInstance, nCmdShow, __argc, __argv);
}

int main(int argc, char** argv) {
    return PatcherMain(GetModuleHandle(NULL), SW_SHOWNORMAL, argc, argv);
}

#else

int main(int argc, char** argv) {
    const bool explicit_gui = argc >= 2 && std::strcmp(argv[1], "--gui") == 0;
#ifdef WARP_NO_GUI
    if (explicit_gui) {
        std::fprintf(stderr, "GUI is not enabled in this build. Use --help.\n");
        return 1;
    }
#else
#ifdef __APPLE__
    const bool has_display = true; // Cocoa does not use DISPLAY.
#else
    const char* display = std::getenv("DISPLAY");
    const char* wayland = std::getenv("WAYLAND_DISPLAY");
    const bool has_display = (display && *display) || (wayland && *wayland);
#endif
    if (explicit_gui && !has_display) {
        std::fprintf(stderr, "Error: Graphical display not available.\n");
        return 1;
    }
    if (explicit_gui || (argc <= 1 && has_display)) return warp::RunGui(argc, argv);
#endif
    return warp::RunCli(argc, argv);
}

#endif
