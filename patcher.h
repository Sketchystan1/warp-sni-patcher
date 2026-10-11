/*
 * WARP SNI Patcher -- shared declarations.
 *
 * The program is split into two translation units:
 *   patcher.c   core: PE parsing, in-place patching, service control
 *   ui.c        Win32 GUI + WinMain
 *
 * The core reports progress through UiLog() (defined in the UI unit); the UI
 * drives patching through the core functions declared here.
 */
#ifndef WARP_SNI_PATCHER_H
#define WARP_SNI_PATCHER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "i18n.h"

/* Embedded application icon (see app.rc). Lowest ID so Explorer uses it. */
#define IDI_APPICON 1

#define DEFAULT_TARGET_PATH \
    "C:\\Program Files\\Cloudflare\\Cloudflare WARP\\warp-svc.exe"
#define DEFAULT_SNI "speed.cloudflare.com"
#define DEFAULT_REG_SNI "api.devices.cloudflare.com"

/* ---- Core (patcher.c) ---- */

/* Patch the target's MASQUE SNI (newSni) and registration API hostname
   (newRegSni). Returns TRUE on success. */
BOOL RunPatch(const char* target, const char* newSni, const char* newRegSni);

/* Restore the original binary from its .bak. Returns TRUE on success. */
BOOL RunRestore(const char* target);

/* Stop the CloudflareWARP service, waiting until stopped. Sets *outWasRunning
   to TRUE if it was running, so the caller knows whether to restart it. */
BOOL StopWarpService(BOOL* outWasRunning);

/* Start the CloudflareWARP service, waiting until running. */
BOOL StartWarpService(void);

/* Delete a stray userenv.dll sitting next to the target (a DLL-sideloading
   artifact). Returns TRUE if there was nothing to do or the delete succeeded. */
BOOL RemoveSideloadedUserenv(const char* target);

/* If WARP reports "Connected" via warp-cli.exe (expected next to the target),
   disconnect it so the tunnel is down before the service is stopped/patched.
   Sets *outWasConnected to TRUE if it was connected, so the caller can restore
   the connection afterward. Best-effort: a missing warp-cli or a query failure
   is not treated as fatal. */
BOOL WarpDisconnectIfConnected(const char* target, BOOL* outWasConnected);

/* Reconnect WARP via warp-cli.exe (expected next to the target). Best-effort:
   a missing warp-cli or a failure is logged but not treated as fatal. */
BOOL WarpConnect(const char* target);

/* TRUE if path exists and is a regular file. */
BOOL FileExists(const char* path);

/* File size in bytes, or (ULONGLONG)-1 if it can't be read. */
ULONGLONG FileSize64(const char* path);

/* Build "<target>.bak" into backup. */
void BuildBackupPath(const char* target, char* backup, size_t backupSize);

/* ---- UI (warp-sni-patcher-ui.c) ---- */

/* Append a formatted line to the GUI log. Used by the core for progress. */
void UiLog(const char* fmt, ...);

#endif /* WARP_SNI_PATCHER_H */
