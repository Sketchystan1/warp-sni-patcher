/*
 * WARP SNI Patcher - Unified Cross-Platform Patching Engine
 * Supports Windows PE64, Linux ELF64, and macOS Mach-O (x86_64 and arm64).
 */

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "patcher.h"
#include "service.h"
#include "formats/formats.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#ifdef __APPLE__
#include <cerrno>
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <crt_externs.h>
#endif

namespace warp {

static LogCallback g_log_cb = nullptr;
static void* g_log_user_data = nullptr;

void SetLogCallback(LogCallback cb, void* user_data) {
    g_log_cb = cb;
    g_log_user_data = user_data;
}

void Log(const char* fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (g_log_cb) {
        g_log_cb(buf, g_log_user_data);
    } else {
        std::fputs(buf, stdout);
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] != '\n') std::fputc('\n', stdout);
        std::fflush(stdout);
    }
}

void ValidateHostname(const std::string& hostname) {
    if (hostname.empty() || hostname.size() > 253)
        throw std::runtime_error("Hostname must contain 1 to 253 ASCII characters.");
    const auto end = hostname.size() - (hostname.back() == '.' ? 1 : 0);
    if (end == 0) throw std::runtime_error("A hostname cannot contain only a dot.");
    std::size_t start = 0;
    while (start < end) {
        auto stop = hostname.find('.', start);
        if (stop == std::string::npos || stop > end) stop = end;
        if (stop == start || stop - start > 63 || hostname[start] == '-' || hostname[stop - 1] == '-')
            throw std::runtime_error("Invalid DNS hostname: " + hostname);
        for (auto i = start; i < stop; ++i) {
            const char c = hostname[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-'))
                throw std::runtime_error("Use an ASCII DNS hostname without a scheme, port, or path.");
        }
        start = stop + 1;
        if (start == end) throw std::runtime_error("Invalid empty DNS label.");
    }
}

std::string BuildBackupPath(const std::string& target) {
    return target + ".bak";
}

bool FileExists(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

Inspection InspectBytes(const Bytes& data) {
#ifdef WARP_HAS_ELF
    if (is_elf(data)) return inspect_elf(data);
#endif
#ifdef WARP_HAS_MACHO
    if (is_macho(data)) return inspect_macho(data);
#endif
#ifdef WARP_HAS_PE
    if (is_pe(data)) return inspect_pe(data);
#endif
    throw std::runtime_error("Unsupported executable format for this build.");
}

PatchResult PatchBytes(const Bytes& data, const PatchOptions& options) {
#ifdef WARP_HAS_ELF
    if (is_elf(data)) return patch_elf(data, options);
#endif
#ifdef WARP_HAS_MACHO
    if (is_macho(data)) return patch_macho(data, options);
#endif
#ifdef WARP_HAS_PE
    if (is_pe(data)) return patch_pe(data, options);
#endif
    throw std::runtime_error("Unsupported executable format for this build.");
}

#if defined(_WIN32) && !defined(WARP_ALL_FORMATS)
bool RunInspect(const std::string& target) {
    return ::RunInspect(target.c_str()) != FALSE;
}

static bool PatchFile(const PatchOptions& options) {
    return ::RunPatch(options.target_path.c_str(),
        options.masque_host ? options.masque_host->c_str() : nullptr,
        options.reg_api_host ? options.reg_api_host->c_str() : nullptr) != FALSE;
}

bool RunRestore(const std::string& target) {
    return ::RunRestore(target.c_str()) != FALSE;
}
#else
static Bytes ReadFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Could not open file: " + path);
    Bytes bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (in.bad()) throw std::runtime_error("Could not read file: " + path);
    return bytes;
}

#ifdef __APPLE__
static void Codesign(std::initializer_list<const char*> arguments) {
    std::vector<char*> argv;
    for (auto arg : arguments) argv.push_back(const_cast<char*>(arg));
    argv.push_back(nullptr);
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0)
        throw std::runtime_error("Could not prepare codesign.");
    int error = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDERR_FILENO);
    pid_t pid = 0;
    if (!error) error = posix_spawn(&pid, "/usr/bin/codesign", &actions, nullptr, argv.data(), *_NSGetEnviron());
    posix_spawn_file_actions_destroy(&actions);
    if (error) throw std::runtime_error("Could not run codesign.");
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw std::runtime_error("macOS signing or signature verification failed; target unchanged.");
}
#endif

// Own only the temporary file we created. Never truncate the target on a failed write.
static void ReplaceFile(const std::string& target, const std::string& source, const Bytes* bytes = nullptr) {
    const auto tmp = target + ".tmp";
    std::filesystem::copy_file(source, tmp); // Fails if a temporary file already exists.
    try {
        if (bytes) {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            out.write(reinterpret_cast<const char*>(bytes->data()), bytes->size());
            out.close();
            if (!out) throw std::runtime_error("Could not write file: " + tmp);
#ifdef __APPLE__
            // An ad-hoc daemon has no vendor Team ID. Preserve its identifier, but
            // not hardened-runtime library validation tied to the vendor identity.
            if (is_macho(*bytes)) {
                Codesign({"codesign", "--force", "--sign", "-", "--options", "0",
                          "--preserve-metadata=identifier", "--timestamp=none", tmp.c_str()});
                Codesign({"codesign", "--verify", "--strict", "--all-architectures", tmp.c_str()});
            }
#endif
        }
#ifdef _WIN32
        if (!MoveFileExA(tmp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            throw std::runtime_error("Could not replace file: " + target);
#else
        std::filesystem::rename(tmp, target);
#endif
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(tmp, ignored);
        throw;
    }
}

bool RunInspect(const std::string& target) {
    try {
        const auto data = ReadFile(target);
#ifdef _WIN32
        if (is_pe(data)) return ::RunInspect(target.c_str()) != FALSE;
#endif
        const auto insp = InspectBytes(data);
        Log("Format: %s", insp.format.c_str());
        Log("MASQUE occurrences: %zu", insp.masque_occurrences);
        Log("Registration occurrences: %zu", insp.registration_occurrences);
        for (const auto& note : insp.notes) Log("Note: %s", note.c_str());
        return true;
    } catch (const std::exception& e) {
        Log("[!] %s", e.what());
        return false;
    }
}

static bool PatchFile(const PatchOptions& options) {
    const auto data = ReadFile(options.target_path);
#ifdef _WIN32
    if (is_pe(data)) return ::RunPatch(options.target_path.c_str(),
        options.masque_host ? options.masque_host->c_str() : nullptr,
        options.reg_api_host ? options.reg_api_host->c_str() : nullptr) != FALSE;
#endif
    const auto result = PatchBytes(data, options);
    const auto backup = BuildBackupPath(options.target_path);
    if (!FileExists(backup)) {
        Log("Backup...");
        std::filesystem::copy_file(options.target_path, backup);
    }
    Log("Patching...");
    ReplaceFile(options.target_path, options.target_path, &result.bytes);
    return true;
}

bool RunRestore(const std::string& target) {
    try {
#ifdef _WIN32
        if (FileExists(target) && is_pe(ReadFile(target))) return ::RunRestore(target.c_str()) != FALSE;
#endif
        const auto backup = BuildBackupPath(target);
        ReplaceFile(target, backup);
        std::filesystem::remove(backup);
        Log("Original file restored from backup.");
        return true;
    } catch (const std::exception& e) {
        Log("[!] %s", e.what());
        return false;
    }
}
#endif

bool RunPatch(const PatchOptions& options) {
    try {
        if (!options.masque_host && !options.reg_api_host)
            throw std::runtime_error("Specify at least one hostname to patch.");
        if (options.masque_host) ValidateHostname(*options.masque_host);
        if (options.reg_api_host) ValidateHostname(*options.reg_api_host);
        return PatchFile(options);
    } catch (const std::exception& e) {
        Log("[!] %s", e.what());
        return false;
    }
}

} // namespace warp

void UiLog(const char* fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    warp::Log("%s", buf);
}
