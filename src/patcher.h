#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#define DEFAULT_TARGET_PATH "C:\\Program Files\\Cloudflare\\Cloudflare WARP\\warp-svc.exe"
#define IDI_APPICON 1
#elif defined(__APPLE__)
#define DEFAULT_TARGET_PATH "/Applications/Cloudflare WARP.app/Contents/Resources/CloudflareWARP"
#else
#define DEFAULT_TARGET_PATH "/usr/bin/warp-svc"
#endif

#define DEFAULT_SNI "speed.cloudflare.com"
#define DEFAULT_REG_SNI "api.devices.cloudflare.com"
#ifdef _WIN32
#ifdef StartService
#undef StartService
#endif
#endif

namespace warp {

using Bytes = std::vector<uint8_t>;

struct PatchOptions {
    std::optional<std::string> masque_host;
    std::optional<std::string> reg_api_host;
    std::string target_path = DEFAULT_TARGET_PATH;
};

struct Inspection {
    std::string format; // "PE", "ELF", "Mach-O"
    std::vector<std::string> architectures;
    size_t masque_occurrences = 0;
    size_t registration_occurrences = 0;
    std::vector<std::string> notes;
};

struct PatchResult {
    Bytes bytes;
    Inspection inspection;
};

// Hostname validation
void ValidateHostname(const std::string& hostname);

// In-memory inspection & patching
Inspection InspectBytes(const Bytes& data);
PatchResult PatchBytes(const Bytes& data, const PatchOptions& options);

// High-level operations on target files
bool RunInspect(const std::string& target);
bool RunPatch(const PatchOptions& options);
bool RunRestore(const std::string& target);

// Utilities
bool FileExists(const std::string& path);
std::string BuildBackupPath(const std::string& target);

// Logging
void Log(const char* fmt, ...);
typedef void (*LogCallback)(const char* text, void* user_data);
void SetLogCallback(LogCallback cb, void* user_data);

} // namespace warp

#ifdef _WIN32
BOOL FileExists(const char* path);
void BuildBackupPath(const char* target, char* backup, size_t backupSize);
BOOL RunPatch(const char* target, const char* newSni, const char* newRegSni);
BOOL RunRestore(const char* target);
BOOL RunInspect(const char* target);
void UiLog(const char* fmt, ...);
#else
void UiLog(const char* fmt, ...);
#endif
