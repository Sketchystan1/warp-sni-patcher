#pragma once

#include <string>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#ifdef StartService
#undef StartService
#endif
#endif

namespace warp {

struct PatchOptions;
bool RunOperation(const PatchOptions& options, bool restore = false);

// High-level service control
bool StopService(bool& was_running);
bool StartService();
bool IsInstalledTarget(const std::string& target);
bool WarpDisconnectIfConnected(const std::string& target, bool* out_was_connected = nullptr);
bool WarpConnect(const std::string& target);

} // namespace warp

#ifdef _WIN32
BOOL StopWarpService(BOOL* outWasRunning);
BOOL StartWarpService(void);
BOOL WarpDisconnectIfConnected(const char* target, BOOL* outWasConnected);
BOOL WarpConnect(const char* target);
#endif
