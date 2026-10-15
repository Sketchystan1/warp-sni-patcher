#include "service.h"
#include "patcher.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <stdexcept>
#include <thread>

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef _WIN32

#define WARP_SERVICE_NAME "CloudflareWARP"
#define SERVICE_WAIT_TIMEOUT_MS 30000
#define SERVICE_POLL_INTERVAL_MS 250

static void GetDirName(const char* path, char* dir, size_t dirSize)
{
    const char* lastSep = NULL;
    const char* p;
    size_t len;

    for (p = path; *p; ++p)
    {
        if (*p == '\\' || *p == '/')
        {
            lastSep = p;
        }
    }

    if (!lastSep)
    {
        dir[0] = '\0';
        return;
    }

    len = (size_t)(lastSep - path);
    if (len >= dirSize)
    {
        len = dirSize - 1;
    }
    memcpy(dir, path, len);
    dir[len] = '\0';
}

BOOL StopWarpService(BOOL* outWasRunning)
{
    SC_HANDLE scm;
    SC_HANDLE svc;
    SERVICE_STATUS status;
    DWORD waited = 0;

    if (outWasRunning)
    {
        *outWasRunning = FALSE;
    }

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
    {
        UiLog("%s", "[!] Could not connect to Windows Service Manager. Please run as Administrator.");
        return FALSE;
    }

    svc = OpenServiceA(scm, WARP_SERVICE_NAME,
                       SERVICE_QUERY_STATUS | SERVICE_STOP);
    if (!svc)
    {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);
        if (err == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            return TRUE;   /* not installed: nothing to control */
        }
        UiLog("%s", "[!] Could not access Cloudflare WARP service.");
        return FALSE;
    }

    if (!QueryServiceStatus(svc, &status))
    {
        UiLog("%s", "[!] Could not check service status.");
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return FALSE;
    }

    if (status.dwCurrentState == SERVICE_STOPPED)
    {
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return TRUE;
    }

    if (outWasRunning)
    {
        *outWasRunning = TRUE;
    }

    UiLog("%s", "Stop service...");
    if (status.dwCurrentState != SERVICE_STOP_PENDING)
    {
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &status))
        {
            UiLog("%s", "[!] Could not stop Cloudflare WARP service.");
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    while (status.dwCurrentState != SERVICE_STOPPED &&
           waited < SERVICE_WAIT_TIMEOUT_MS)
    {
        Sleep(SERVICE_POLL_INTERVAL_MS);
        waited += SERVICE_POLL_INTERVAL_MS;
        if (!QueryServiceStatus(svc, &status))
        {
            break;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (status.dwCurrentState != SERVICE_STOPPED)
    {
        UiLog("%s", "[!] Cloudflare WARP service took too long to stop.");
        return FALSE;
    }

    return TRUE;
}

BOOL StartWarpService(void)
{
    SC_HANDLE scm;
    SC_HANDLE svc;
    SERVICE_STATUS status;
    DWORD waited = 0;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
    {
        UiLog("%s", "[!] Could not connect to Windows Service Manager. Please run as Administrator.");
        return FALSE;
    }

    svc = OpenServiceA(scm, WARP_SERVICE_NAME,
                       SERVICE_QUERY_STATUS | SERVICE_START);
    if (!svc)
    {
        UiLog("%s", "[!] Could not open Cloudflare WARP service to start it.");
        CloseServiceHandle(scm);
        return FALSE;
    }

    UiLog("%s", "Start service...");
    if (!StartServiceA(svc, 0, NULL))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING)
        {
            UiLog("%s", "[!] Could not start Cloudflare WARP service.");
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    if (!QueryServiceStatus(svc, &status))
    {
        status.dwCurrentState = SERVICE_START_PENDING;
    }

    while (status.dwCurrentState != SERVICE_RUNNING &&
           waited < SERVICE_WAIT_TIMEOUT_MS)
    {
        Sleep(SERVICE_POLL_INTERVAL_MS);
        waited += SERVICE_POLL_INTERVAL_MS;
        if (!QueryServiceStatus(svc, &status))
        {
            break;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (status.dwCurrentState != SERVICE_RUNNING)
    {
        UiLog("%s", "[!] Cloudflare WARP service took too long to start.");
        return FALSE;
    }

    return TRUE;
}

static BOOL RunAndCapture(const char* cmdLine, const char* workDir,
                          char* out, size_t outSize, DWORD* outExit)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE readPipe = NULL, writePipe = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char cmd[MAX_PATH * 4];
    size_t total = 0;
    BOOL ok = FALSE;

    out[0] = '\0';
    if (outExit)
    {
        *outExit = (DWORD)-1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&readPipe, &writePipe, &sa, 0))
    {
        return FALSE;
    }
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    memset(&pi, 0, sizeof(pi));

    _snprintf(cmd, sizeof(cmd), "%s", cmdLine);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, workDir, &si, &pi))
    {
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        return FALSE;
    }

    CloseHandle(writePipe);
    writePipe = NULL;

    for (;;)
    {
        DWORD got = 0;
        if (!ReadFile(readPipe, out + total,
                      (DWORD)(outSize - 1 - total), &got, NULL) || got == 0)
        {
            break;
        }
        total += got;
        if (total >= outSize - 1)
        {
            break;
        }
    }
    out[total] = '\0';

    WaitForSingleObject(pi.hProcess, SERVICE_WAIT_TIMEOUT_MS);
    if (outExit)
    {
        GetExitCodeProcess(pi.hProcess, outExit);
    }
    ok = TRUE;

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(readPipe);
    return ok;
}

static BOOL ContainsNoCase(const char* haystack, const char* needle)
{
    size_t nlen = strlen(needle);
    const char* p;
    if (nlen == 0) return TRUE;
    for (p = haystack; *p; ++p)
    {
        if (_strnicmp(p, needle, nlen) == 0) return TRUE;
    }
    return FALSE;
}

static BOOL ContainsWordNoCase(const char* haystack, const char* needle)
{
    size_t nlen = strlen(needle);
    const char* p;
    if (nlen == 0) return TRUE;
    for (p = haystack; *p; ++p)
    {
        if (_strnicmp(p, needle, nlen) == 0)
        {
            BOOL leftOk = (p == haystack) || !isalpha((unsigned char)*(p - 1));
            BOOL rightOk = !isalpha((unsigned char)*(p + nlen));
            if (leftOk && rightOk) return TRUE;
        }
    }
    return FALSE;
}

static BOOL FindWarpCli(const char* target, char* cli, size_t cliSize)
{
    char dir[MAX_PATH * 2];
    GetDirName(target, dir, sizeof(dir));
    if (dir[0] == '\0') return FALSE;

    _snprintf(cli, cliSize, "%s\\warp-cli.exe", dir);
    cli[cliSize - 1] = '\0';

    return FileExists(cli);
}

BOOL WarpDisconnectIfConnected(const char* target, BOOL* outWasConnected)
{
    char cli[MAX_PATH * 2];
    char cmd[MAX_PATH * 4];
    char output[4096];
    DWORD exitCode = 0;

    if (outWasConnected) *outWasConnected = FALSE;

    if (!FindWarpCli(target, cli, sizeof(cli)))
    {
        return TRUE;
    }

    _snprintf(cmd, sizeof(cmd), "\"%s\" status", cli);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!RunAndCapture(cmd, NULL, output, sizeof(output), &exitCode))
    {
        return TRUE;
    }

    if (ContainsNoCase(output, "Disconnected") || !ContainsWordNoCase(output, "Connected"))
    {
        return TRUE;
    }

    if (outWasConnected) *outWasConnected = TRUE;

    UiLog("%s", "Disconnecting...");
    _snprintf(cmd, sizeof(cmd), "\"%s\" disconnect", cli);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!RunAndCapture(cmd, NULL, output, sizeof(output), &exitCode))
    {
        return TRUE;
    }

    return TRUE;
}

BOOL WarpConnect(const char* target)
{
    char cli[MAX_PATH * 2];
    char cmd[MAX_PATH * 4];
    char output[4096];
    DWORD exitCode = 0;

    if (!FindWarpCli(target, cli, sizeof(cli)))
    {
        return TRUE;
    }

    _snprintf(cmd, sizeof(cmd), "\"%s\" connect", cli);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!RunAndCapture(cmd, NULL, output, sizeof(output), &exitCode))
    {
        UiLog("%s", "Note: You can reconnect the tunnel using the Cloudflare WARP app.");
        return FALSE;
    }

    return TRUE;
}

#endif // _WIN32

namespace warp {

bool IsInstalledTarget(const std::string& target) {
    if (target.empty()) return false;
    std::error_code ec;
    if (std::filesystem::equivalent(target, DEFAULT_TARGET_PATH, ec)) {
        return true;
    }
    ec.clear();
    auto p1 = std::filesystem::weakly_canonical(target, ec);
    if (!ec) {
        std::error_code ec2;
        auto p2 = std::filesystem::weakly_canonical(DEFAULT_TARGET_PATH, ec2);
        if (!ec2 && p1 == p2) return true;
    }
#ifdef _WIN32
    std::string s1 = target, s2 = DEFAULT_TARGET_PATH;
    std::transform(s1.begin(), s1.end(), s1.begin(), [](unsigned char c) { return (char)::tolower(c); });
    std::transform(s2.begin(), s2.end(), s2.begin(), [](unsigned char c) { return (char)::tolower(c); });
    if (s1 == s2) return true;
#endif
    return false;
}

#ifndef _WIN32
static std::string FindWarpCliPath(const std::string& target) {
    std::error_code ec;
    std::filesystem::path tp(target);
    std::filesystem::path dir = tp.parent_path();
#ifdef _WIN32
    std::string cli_name = "warp-cli.exe";
#else
    std::string cli_name = "warp-cli";
#endif
    if (!dir.empty()) {
        std::filesystem::path candidate = dir / cli_name;
        if (std::filesystem::exists(candidate, ec)) {
            return candidate.string();
        }
    }
#ifdef __APPLE__
    const char* standard_paths[] = {
        "/Applications/Cloudflare WARP.app/Contents/Resources/warp-cli",
        "/usr/local/bin/warp-cli",
        "/opt/homebrew/bin/warp-cli"
    };
    for (const char* p : standard_paths) {
        if (std::filesystem::exists(p, ec)) return p;
    }
#elif !defined(_WIN32)
    const char* standard_paths[] = {
        "/usr/bin/warp-cli",
        "/usr/local/bin/warp-cli"
    };
    for (const char* p : standard_paths) {
        if (std::filesystem::exists(p, ec)) return p;
    }
#endif
    return "";
}

static bool RunPosixCommand(const std::string& cmd, std::string* output = nullptr, int* exit_code = nullptr) {
    std::string full_cmd = cmd + " 2>&1";
    FILE* fp = popen(full_cmd.c_str(), "r");
    if (!fp) {
        if (exit_code) *exit_code = -1;
        return false;
    }
    char buf[512];
    std::string out;
    while (fgets(buf, sizeof(buf), fp)) {
        out += buf;
    }
    int status = pclose(fp);
    int code = -1;
    if (WIFEXITED(status)) {
        code = WEXITSTATUS(status);
    }
    if (exit_code) *exit_code = code;
    if (output) *output = out;
    return (code == 0);
}

static bool CaseInsensitiveContains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        }
    );
    return it != haystack.end();
}
#endif

bool WarpDisconnectIfConnected(const std::string& target, bool* out_was_connected) {
    if (out_was_connected) *out_was_connected = false;
#ifdef _WIN32
    BOOL wc = FALSE;
    BOOL ok = ::WarpDisconnectIfConnected(target.c_str(), &wc);
    if (out_was_connected) *out_was_connected = (wc != FALSE);
    return ok != FALSE;
#else
    std::string cli = FindWarpCliPath(target);
    if (cli.empty()) {
        return true;
    }

    std::string output;
    int exit_code = 0;
    std::string cmd = "\"" + cli + "\" status";
    if (!RunPosixCommand(cmd, &output, &exit_code)) {
        return true;
    }

    if (CaseInsensitiveContains(output, "Disconnected") || !CaseInsensitiveContains(output, "Connected")) {
        return true;
    }

    if (out_was_connected) *out_was_connected = true;

    Log("Disconnecting...");
    std::string disc_cmd = "\"" + cli + "\" disconnect";
    if (RunPosixCommand(disc_cmd, &output, &exit_code)) return true;
    Log("[!] Could not disconnect WARP.");
    return false;
#endif
}

bool WarpConnect(const std::string& target) {
#ifdef _WIN32
    return ::WarpConnect(target.c_str()) != FALSE;
#else
    std::string cli = FindWarpCliPath(target);
    if (cli.empty()) {
        return true;
    }

    Log("Reconnecting...");
    std::string output;
    int exit_code = 0;
    std::string cmd = "\"" + cli + "\" connect";
    if (!RunPosixCommand(cmd, &output, &exit_code)) {
        Log("Note: You can reconnect the tunnel using the Cloudflare WARP app or warp-cli.");
        return false;
    }
#ifdef __APPLE__
    for (int i = 0; i < 60; ++i) {
        if (RunPosixCommand("\"" + cli + "\" status", &output)) {
            if (CaseInsensitiveContains(output, "Connected") &&
                !CaseInsensitiveContains(output, "Disconnected")) return true;
            if (CaseInsensitiveContains(output, "Registration Missing")) {
                Log("[!] WARP needs registration. Register in the Cloudflare WARP app, then connect.");
                return false;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    Log("[!] WARP did not reconnect. Check its status in the Cloudflare WARP app.");
    return false;
#else
    return true;
#endif
#endif
}

#if !defined(_WIN32) && !defined(__APPLE__)
static bool IsServiceRunningLinux() {
    int ec = 0;
    RunPosixCommand("systemctl is-active --quiet warp-svc", nullptr, &ec);
    if (ec == 0) return true;

    RunPosixCommand("pgrep -x warp-svc >/dev/null 2>&1 || pidof warp-svc >/dev/null 2>&1", nullptr, &ec);
    return (ec == 0);
}

static bool StopServiceLinux() {
    Log("Stop service...");
    int ec = 0;
    bool systemctl_ok = RunPosixCommand("systemctl stop warp-svc", nullptr, &ec);
    if (systemctl_ok && ec == 0) {
        for (int i = 0; i < 40; ++i) {
            if (!IsServiceRunningLinux()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
        }
    }

    RunPosixCommand("pkill -TERM -x warp-svc", nullptr, &ec);
    for (int i = 0; i < 20; ++i) {
        if (!IsServiceRunningLinux()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    return !IsServiceRunningLinux();
}

static bool StartServiceLinux() {
    Log("Start service...");
    int ec = 0;
    if (RunPosixCommand("systemctl start warp-svc", nullptr, &ec) && ec == 0) {
        return true;
    }
    Log("[~] Note: Could not start warp-svc with systemctl. If not using systemd, start warp-svc manually.");
    return false;
}
#endif

#ifdef __APPLE__
static constexpr const char* kMacService = "system/com.cloudflare.1dot1dot1dot1.macos.warp.daemon";
static constexpr const char* kMacPlist = "/Library/LaunchDaemons/com.cloudflare.1dot1dot1dot1.macos.warp.daemon.plist";

static bool IsServiceLoadedMac() {
    return RunPosixCommand(std::string("/bin/launchctl print ") + kMacService);
}

static bool IsServiceRunningMac() {
    return RunPosixCommand("/usr/bin/pgrep -x CloudflareWARP");
}

static bool CanChangeSigningIdentityMac(const std::string& target) {
    const auto cli = FindWarpCliPath(target);
    if (!cli.empty() && RunPosixCommand("\"" + cli + "\" registration show")) {
        Log("[!] Remove WARP registration before Patch or Restore: warp-cli registration delete");
        Log("This resets the device registration. Afterward, register again (personal WARP: warp-cli registration new).");
        return false;
    }
    return true;
}

static bool StopServiceMac() {
    Log("Stop service...");
    if (IsServiceLoadedMac() &&
        !RunPosixCommand(std::string("/bin/launchctl bootout system ") + kMacPlist)) return false;
    // Also handle a daemon launched directly, outside launchd.
    if (IsServiceRunningMac()) RunPosixCommand("/usr/bin/pkill -TERM -x CloudflareWARP");
    for (int i = 0; i < 40; ++i) {
        if (!IsServiceRunningMac()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    return !IsServiceRunningMac();
}

static bool StartServiceMac() {
    Log("Start service...");
    if (!IsServiceLoadedMac() &&
        !RunPosixCommand(std::string("/bin/launchctl bootstrap system ") + kMacPlist)) return false;
    RunPosixCommand(std::string("/bin/launchctl kickstart ") + kMacService);
    const auto cli = FindWarpCliPath(DEFAULT_TARGET_PATH);
    int ready = 0;
    for (int i = 0; i < 60; ++i) {
        if (IsServiceRunningMac() && !cli.empty() && RunPosixCommand("\"" + cli + "\" status")) {
            if (++ready == 4) return true; // IPC must stay available across multiple polls.
        } else ready = 0;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    Log("[!] WARP daemon did not become ready.");
    return false;
}
#endif

bool StopService(bool& was_running) {
#ifdef _WIN32
    BOOL wr = FALSE;
    BOOL ok = StopWarpService(&wr);
    was_running = (wr != FALSE);
    return ok != FALSE;
#elif defined(__APPLE__)
    bool was = IsServiceLoadedMac() || IsServiceRunningMac();
    was_running = was;
    if (!was) return true;
    return StopServiceMac();
#else
    bool was = IsServiceRunningLinux();
    was_running = was;
    if (!was) return true;
    return StopServiceLinux();
#endif
}

bool StartService() {
#ifdef _WIN32
    return StartWarpService() != FALSE;
#elif defined(__APPLE__)
    return StartServiceMac();
#else
    return StartServiceLinux();
#endif
}

bool RunOperation(const PatchOptions& options, bool restore) {
    // Reject input before disconnecting an installed service.
    if (!restore) {
        try {
            if (!options.masque_host && !options.reg_api_host)
                throw std::runtime_error("Specify at least one hostname to patch.");
            if (options.masque_host) ValidateHostname(*options.masque_host);
            if (options.reg_api_host) ValidateHostname(*options.reg_api_host);
        } catch (const std::exception& e) {
            Log("[!] %s", e.what());
            return false;
        }
    }
    if (!FileExists(restore ? BuildBackupPath(options.target_path) : options.target_path)) {
        Log("[!] %s file not found: %s", restore ? "Backup" : "Target", options.target_path.c_str());
        return false;
    }
    const bool installed = IsInstalledTarget(options.target_path);
#ifdef __APPLE__
    // Keychain credentials belong to their creating signature. Never strand an
    // existing registration under a different identity or silently delete it.
    if (installed && !CanChangeSigningIdentityMac(options.target_path)) return false;
#endif
    bool was_running = false, was_connected = false;
    if (installed) {
        if (!WarpDisconnectIfConnected(options.target_path, &was_connected)) return false;
        if (!StopService(was_running)) {
            Log("[!] Could not stop WARP service. Run as Administrator/root.");
            if (was_running) StartService();
            if (was_connected) WarpConnect(options.target_path);
            return false;
        }
    }
    bool ok = restore ? RunRestore(options.target_path) : RunPatch(options);
    if (installed && was_running) {
        if (!StartService()) {
#ifdef __APPLE__
            if (ok && !restore) {
                Log("[!] Startup failed; restoring backup...");
                if (StopServiceMac() && RunRestore(options.target_path) && StartService() && was_connected)
                    WarpConnect(options.target_path);
            }
#endif
            ok = false;
        }
        else if (was_connected && !WarpConnect(options.target_path)) ok = false;
    }
    if (ok) Log("Done!");
    return ok;
}


} // namespace warp
