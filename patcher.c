/*
 * WARP SNI Patcher -- core (PE parsing, in-place patching, service control).
 *
 * Standalone on-disk binary patcher for Cloudflare WARP's warp-svc.exe. It
 * overrides the MASQUE SNI hostname(s) baked into the binary.
 *
 * Strategy (in-place overwrite):
 *   For each known MASQUE hostname found in the binary's data sections, the
 *   string bytes are overwritten in place with the new SNI. Because the string
 *   keeps its original address, no Rust &'static str fat-pointer or LEA
 *   repointing is required -- only the length values need fixing:
 *     1. Fat-pointer length fields in data ([8-byte ptr][8-byte len]) whose ptr
 *        matches the hostname's preferred VA.
 *     2. `mov r32, imm32` length immediates in code, but only within a small
 *        window around a `lea reg,[rip+disp]` that targets a matched hostname,
 *        so unrelated constants elsewhere are never touched.
 *
 * The original binary is preserved as <target>.bak. The backup is refreshed
 * whenever the target still contains the MASQUE hostnames (a pristine install
 * or a fresh WARP update), so re-running with a different SNI stays clean and a
 * WARP update never leaves a stale backup behind.
 *
 * NOTE: patching breaks warp-svc.exe's Authenticode signature, and WARP updates
 * replace the binary, so the patcher must be re-run after each update.
 */

#include "patcher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BACKUP_SUFFIX ".bak"
#define RIP_RELATIVE_LEA_SIZE 7
#define STATIC_CODE_PATCH_WINDOW_BEFORE 16
#define STATIC_CODE_PATCH_WINDOW_AFTER 24
#define MAX_OCCURRENCES 256

typedef struct KNOWN_SNI_TAG
{
    const char* value;
    size_t length;
} KNOWN_SNI;

static const KNOWN_SNI g_KnownHostnames[] = {
    { "consumer-masque.cloudflareclient.com", 36 },
    { "consumer-masque.cloudflareclient.com.", 37 },
    { "consumer-masque-proxy.cloudflareclient.com", 42 },
    { "consumer-masque-proxy.cloudflareclient.com.", 43 },
    { "zt-masque.cloudflareclient.com", 30 },
    { "zt-masque.cloudflareclient.com.", 31 },
    { "zt-masque-proxy.cloudflareclient.com", 36 },
    { "zt-masque-proxy.cloudflareclient.com.", 37 }
};

/* A located hostname occurrence in the on-disk image. */
typedef struct OCCURRENCE_TAG
{
    size_t fileOffset;      /* byte offset within the file buffer */
    ULONGLONG virtualAddr;  /* preferred VA = ImageBase + RVA */
    size_t originalLength;  /* length of the matched hostname */
} OCCURRENCE;

typedef struct PE_VIEW_TAG
{
    unsigned char* base;
    size_t size;
    IMAGE_NT_HEADERS64* nt;
    IMAGE_SECTION_HEADER* sections;
    WORD sectionCount;
    ULONGLONG imageBase;
} PE_VIEW;

static unsigned char* ReadWholeFile(const char* path, size_t* outSize)
{
    HANDLE file;
    LARGE_INTEGER fileSize;
    unsigned char* buffer;
    DWORD toRead;
    DWORD readTotal = 0;

    file = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        UiLog("[!] Cannot open '%s' (error %lu).", path, GetLastError());
        return NULL;
    }

    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > (LONGLONG)0x7FFFFFFF)
    {
        UiLog("[!] Unexpected file size for '%s'.", path);
        CloseHandle(file);
        return NULL;
    }

    buffer = (unsigned char*)malloc((size_t)fileSize.QuadPart);
    if (!buffer)
    {
        UiLog("[!] Out of memory reading '%s'.", path);
        CloseHandle(file);
        return NULL;
    }

    toRead = (DWORD)fileSize.QuadPart;
    while (readTotal < toRead)
    {
        DWORD chunk = 0;
        if (!ReadFile(file, buffer + readTotal, toRead - readTotal, &chunk, NULL) ||
            chunk == 0)
        {
            UiLog("[!] Read error on '%s' (error %lu).", path, GetLastError());
            free(buffer);
            CloseHandle(file);
            return NULL;
        }
        readTotal += chunk;
    }

    CloseHandle(file);
    *outSize = (size_t)fileSize.QuadPart;
    return buffer;
}

static BOOL WriteWholeFile(const char* path, const unsigned char* data, size_t size)
{
    HANDLE file;
    DWORD written = 0;
    size_t total = 0;

    file = CreateFileA(
        path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        UiLog("[!] Cannot write '%s' (error %lu). Run as Administrator?",
              path, GetLastError());
        return FALSE;
    }

    while (total < size)
    {
        DWORD chunk = (size - total > 0x10000000) ? 0x10000000 : (DWORD)(size - total);
        if (!WriteFile(file, data + total, chunk, &written, NULL))
        {
            UiLog("[!] Write error on '%s' (error %lu).", path, GetLastError());
            CloseHandle(file);
            return FALSE;
        }
        total += written;
    }

    CloseHandle(file);
    return TRUE;
}

BOOL FileExists(const char* path)
{
    DWORD attrs = GetFileAttributesA(path);
    return attrs != INVALID_FILE_ATTRIBUTES &&
           (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

/* Return the file's size in bytes, or (ULONGLONG)-1 if it can't be read. */
ULONGLONG FileSize64(const char* path)
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad))
    {
        return (ULONGLONG)-1;
    }
    return ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
}

static BOOL ParsePe(unsigned char* base, size_t size, PE_VIEW* view)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;

    memset(view, 0, sizeof(*view));

    if (size < sizeof(IMAGE_DOS_HEADER))
    {
        UiLog("[!] File too small to be a PE image.");
        return FALSE;
    }

    dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        UiLog("[!] Not a PE image (bad DOS signature).");
        return FALSE;
    }

    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size)
    {
        UiLog("[!] Malformed PE (NT headers out of range).");
        return FALSE;
    }

    nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        UiLog("[!] Not a PE image (bad NT signature).");
        return FALSE;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        UiLog("[!] Only 64-bit (x64) PE images are supported.");
        return FALSE;
    }

    view->base = base;
    view->size = size;
    view->nt = nt;
    view->sections = IMAGE_FIRST_SECTION(nt);
    view->sectionCount = nt->FileHeader.NumberOfSections;
    view->imageBase = nt->OptionalHeader.ImageBase;
    return TRUE;
}

static BOOL IsDataSection(const IMAGE_SECTION_HEADER* s)
{
    return s->SizeOfRawData > 0 &&
           (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 &&
           ((s->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 ||
            (s->Characteristics & IMAGE_SCN_MEM_WRITE) != 0);
}

static BOOL IsCodeSection(const IMAGE_SECTION_HEADER* s)
{
    return s->SizeOfRawData > 0 &&
           (s->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

/* Locate every occurrence of the known hostnames inside data sections. */
static size_t CollectOccurrences(
    const PE_VIEW* view,
    OCCURRENCE* out,
    size_t maxOut)
{
    size_t count = 0;
    WORD si;
    size_t hi;

    for (si = 0; si < view->sectionCount && count < maxOut; ++si)
    {
        const IMAGE_SECTION_HEADER* s = &view->sections[si];
        unsigned char* secBase;
        size_t secSize;
        size_t off;

        if (!IsDataSection(s))
        {
            continue;
        }

        secBase = view->base + s->PointerToRawData;
        secSize = s->SizeOfRawData;
        if (s->PointerToRawData + secSize > view->size)
        {
            secSize = view->size - s->PointerToRawData;
        }

        for (off = 0; off < secSize && count < maxOut; ++off)
        {
            const KNOWN_SNI* best = NULL;

            /* Pick the longest hostname that matches here, so trailing-dot and
               "-proxy" variants win over their shorter prefixes. */
            for (hi = 0; hi < sizeof(g_KnownHostnames) / sizeof(g_KnownHostnames[0]); ++hi)
            {
                const KNOWN_SNI* known = &g_KnownHostnames[hi];
                if (off + known->length > secSize)
                {
                    continue;
                }
                if (memcmp(secBase + off, known->value, known->length) != 0)
                {
                    continue;
                }
                if (!best || known->length > best->length)
                {
                    best = known;
                }
            }

            if (best)
            {
                out[count].fileOffset = s->PointerToRawData + off;
                out[count].virtualAddr =
                    view->imageBase + s->VirtualAddress + off;
                out[count].originalLength = best->length;
                count++;
                /* Skip past this occurrence to avoid a prefix re-match inside it. */
                off += best->length - 1;
            }
        }
    }

    return count;
}

/* Overwrite the leading bytes of the hostname in place with the new SNI.
   The tail (originalLength - newLen) is deliberately left untouched: Rust &str
   is (ptr, len) with no NUL terminator, so the patched length alone bounds every
   read, and preserving the tail avoids corrupting any string the linker
   tail-merged into this one (e.g. a shared "cloudflareclient.com" suffix). */
static void OverwriteHostname(
    PE_VIEW* view,
    const OCCURRENCE* occ,
    const char* newSni,
    size_t newLen)
{
    unsigned char* dst = view->base + occ->fileOffset;
    memcpy(dst, newSni, newLen);
}

/* Rewrite Rust &'static str fat-pointer length fields ([ptr][len]) whose ptr
   matches a patched hostname VA and whose len matches the original length. */
static DWORD PatchFatPointerLengths(
    PE_VIEW* view,
    const OCCURRENCE* occs,
    size_t occCount,
    size_t newLen)
{
    DWORD patched = 0;
    WORD si;

    for (si = 0; si < view->sectionCount; ++si)
    {
        const IMAGE_SECTION_HEADER* s = &view->sections[si];
        unsigned char* secBase;
        size_t secSize;
        size_t off;

        if (!IsDataSection(s))
        {
            continue;
        }

        secBase = view->base + s->PointerToRawData;
        secSize = s->SizeOfRawData;
        if (s->PointerToRawData + secSize > view->size)
        {
            secSize = view->size - s->PointerToRawData;
        }
        if (secSize < sizeof(ULONGLONG) * 2)
        {
            continue;
        }

        for (off = 0; off + sizeof(ULONGLONG) * 2 <= secSize; ++off)
        {
            ULONGLONG refVa;
            ULONGLONG refLen;
            size_t oi;

            memcpy(&refVa, secBase + off, sizeof(refVa));
            memcpy(&refLen, secBase + off + sizeof(refVa), sizeof(refLen));

            for (oi = 0; oi < occCount; ++oi)
            {
                if (refVa == occs[oi].virtualAddr &&
                    refLen == (ULONGLONG)occs[oi].originalLength)
                {
                    ULONGLONG newLen64 = (ULONGLONG)newLen;
                    memcpy(secBase + off + sizeof(refVa), &newLen64, sizeof(newLen64));
                    patched++;
                    break;
                }
            }
        }
    }

    return patched;
}

/* Resolve `lea reg,[rip+disp32]` (REX.W 8D /r) to its target VA. */
static BOOL ResolveLeaTargetVa(
    const PE_VIEW* view,
    const IMAGE_SECTION_HEADER* sec,
    size_t secOffset,
    ULONGLONG* outVa)
{
    const unsigned char* p = view->base + sec->PointerToRawData + secOffset;
    LONG disp;
    ULONGLONG ripVa;

    if ((p[0] != 0x48 && p[0] != 0x49 && p[0] != 0x4C && p[0] != 0x4D) ||
        p[1] != 0x8D)
    {
        return FALSE;
    }

    switch (p[2])
    {
    case 0x05: case 0x0D: case 0x15: case 0x1D:
    case 0x25: case 0x2D: case 0x35: case 0x3D:
        break;
    default:
        return FALSE;
    }

    memcpy(&disp, p + 3, sizeof(disp));
    /* VA of the instruction, then rip points past the 7-byte instruction. */
    ripVa = view->imageBase + sec->VirtualAddress + secOffset + RIP_RELATIVE_LEA_SIZE;
    *outVa = ripVa + (LONGLONG)disp;
    return TRUE;
}

/* Patch `mov r32, imm32` immediates equal to origLen -> newLen within a range. */
static DWORD PatchLengthImmediatesInRange(
    unsigned char* start,
    size_t rangeLen,
    DWORD origLen,
    DWORD newLen)
{
    DWORD patched = 0;
    size_t off;

    for (off = 0; off + 5 <= rangeLen; ++off)
    {
        DWORD value;

        /* B8..BF: mov r32, imm32 */
        if (start[off] >= 0xB8 && start[off] <= 0xBF)
        {
            memcpy(&value, start + off + 1, sizeof(value));
            if (value == origLen)
            {
                memcpy(start + off + 1, &newLen, sizeof(newLen));
                patched++;
                off += 4;
            }
            continue;
        }

        /* 41 B8..BF: mov r8d..r15d, imm32 */
        if (off + 6 <= rangeLen &&
            start[off] == 0x41 &&
            start[off + 1] >= 0xB8 && start[off + 1] <= 0xBF)
        {
            memcpy(&value, start + off + 2, sizeof(value));
            if (value == origLen)
            {
                memcpy(start + off + 2, &newLen, sizeof(newLen));
                patched++;
                off += 5;
            }
        }
    }

    return patched;
}

/* Scan code sections for LEAs that load a patched hostname, then fix nearby
   length immediates so the code passes the new (shorter) length. */
static DWORD PatchCodeLengthImmediates(
    PE_VIEW* view,
    const OCCURRENCE* occs,
    size_t occCount,
    size_t newLen)
{
    DWORD patched = 0;
    WORD si;

    for (si = 0; si < view->sectionCount; ++si)
    {
        const IMAGE_SECTION_HEADER* s = &view->sections[si];
        size_t secSize;
        size_t off;

        if (!IsCodeSection(s))
        {
            continue;
        }

        secSize = s->SizeOfRawData;
        if (s->PointerToRawData + secSize > view->size)
        {
            secSize = view->size - s->PointerToRawData;
        }
        if (secSize < RIP_RELATIVE_LEA_SIZE)
        {
            continue;
        }

        for (off = 0; off + RIP_RELATIVE_LEA_SIZE <= secSize; ++off)
        {
            ULONGLONG targetVa;
            size_t oi;
            const OCCURRENCE* matched = NULL;

            if (!ResolveLeaTargetVa(view, s, off, &targetVa))
            {
                continue;
            }

            for (oi = 0; oi < occCount; ++oi)
            {
                if (targetVa == occs[oi].virtualAddr)
                {
                    matched = &occs[oi];
                    break;
                }
            }

            if (!matched)
            {
                continue;
            }

            {
                size_t winStart = off > STATIC_CODE_PATCH_WINDOW_BEFORE
                    ? off - STATIC_CODE_PATCH_WINDOW_BEFORE
                    : 0;
                size_t winEnd = off + RIP_RELATIVE_LEA_SIZE + STATIC_CODE_PATCH_WINDOW_AFTER;
                if (winEnd > secSize)
                {
                    winEnd = secSize;
                }

                patched += PatchLengthImmediatesInRange(
                    view->base + s->PointerToRawData + winStart,
                    winEnd - winStart,
                    (DWORD)matched->originalLength,
                    (DWORD)newLen);
            }
        }
    }

    return patched;
}

void BuildBackupPath(const char* target, char* backup, size_t backupSize)
{
    _snprintf(backup, backupSize, "%s%s", target, BACKUP_SUFFIX);
    backup[backupSize - 1] = '\0';
}

/* ---- Service control ---- */

#define WARP_SERVICE_NAME "CloudflareWARP"
#define SERVICE_WAIT_TIMEOUT_MS 30000
#define SERVICE_POLL_INTERVAL_MS 250

/* Stop the CloudflareWARP service and wait until it is fully stopped.
   Sets *outWasRunning to TRUE if the service was running (or start-pending)
   when we opened it, so the caller knows whether to restart it afterward.
   Returns TRUE if the service is stopped (or absent) by the time we return. */
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
        UiLog("[!] Cannot open Service Control Manager (error %lu).", GetLastError());
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
        UiLog("[!] Cannot open service '%s' (error %lu).", WARP_SERVICE_NAME, err);
        return FALSE;
    }

    if (!QueryServiceStatus(svc, &status))
    {
        UiLog("[!] Cannot query service status (error %lu).", GetLastError());
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

    if (status.dwCurrentState != SERVICE_STOP_PENDING)
    {
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &status))
        {
            UiLog("[!] Failed to send stop control (error %lu).", GetLastError());
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
        UiLog("[!] Service did not stop within %d seconds.",
              SERVICE_WAIT_TIMEOUT_MS / 1000);
        return FALSE;
    }

    return TRUE;
}

/* Start the CloudflareWARP service and wait until it is running. */
BOOL StartWarpService(void)
{
    SC_HANDLE scm;
    SC_HANDLE svc;
    SERVICE_STATUS status;
    DWORD waited = 0;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
    {
        UiLog("[!] Cannot open Service Control Manager (error %lu).", GetLastError());
        return FALSE;
    }

    svc = OpenServiceA(scm, WARP_SERVICE_NAME,
                       SERVICE_QUERY_STATUS | SERVICE_START);
    if (!svc)
    {
        UiLog("[!] Cannot open service '%s' to start it (error %lu).",
              WARP_SERVICE_NAME, GetLastError());
        CloseServiceHandle(scm);
        return FALSE;
    }

    if (!StartServiceA(svc, 0, NULL))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING)
        {
            UiLog("[!] Failed to start service (error %lu).", err);
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
        UiLog("[!] Service did not reach running state within %d seconds.",
              SERVICE_WAIT_TIMEOUT_MS / 1000);
        return FALSE;
    }

    return TRUE;
}

/* ---- Pre-patch cleanup / tunnel handling ---- */

/* Copy the directory portion of a path (everything up to the last separator)
   into dir. If there is no separator, dir is set to empty. */
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

/* Delete a stray userenv.dll sitting next to the target. A userenv.dll planted
   in the service directory is a classic DLL-sideloading vector: warp-svc.exe
   would load it in preference to the real one in System32. We remove it before
   patching so the freshly patched service does not start against a hijack DLL. */
BOOL RemoveSideloadedUserenv(const char* target)
{
    char dir[MAX_PATH * 2];
    char dll[MAX_PATH * 2];

    GetDirName(target, dir, sizeof(dir));
    if (dir[0] == '\0')
    {
        return TRUE;   /* no directory component; nothing to check */
    }

    _snprintf(dll, sizeof(dll), "%s\\userenv.dll", dir);
    dll[sizeof(dll) - 1] = '\0';

    if (!FileExists(dll))
    {
        return TRUE;   /* clean: no sideloaded DLL present */
    }

    UiLog("[*] Found userenv.dll next to warp-svc.exe; deleting it.");
    if (!DeleteFileA(dll))
    {
        UiLog("[!] Failed to delete '%s' (error %lu).", dll, GetLastError());
        return FALSE;
    }

    UiLog("[+] Removed %s.", dll);
    return TRUE;
}

/* Run cmdLine (with its working directory set to workDir if non-NULL) and
   capture up to outSize-1 bytes of its stdout+stderr into out. Returns TRUE and
   sets *outExit to the process exit code on success. */
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
    /* The read end must not be inherited by the child. */
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    memset(&pi, 0, sizeof(pi));

    /* CreateProcess may modify the command-line buffer, so use a writable copy. */
    _snprintf(cmd, sizeof(cmd), "%s", cmdLine);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, workDir, &si, &pi))
    {
        CloseHandle(readPipe);
        CloseHandle(writePipe);
        return FALSE;
    }

    /* Close our copy of the write end so the read returns EOF when the child
       exits; then drain the pipe. */
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

/* Case-insensitive substring search. */
static BOOL ContainsNoCase(const char* haystack, const char* needle)
{
    size_t nlen = strlen(needle);
    const char* p;
    if (nlen == 0)
    {
        return TRUE;
    }
    for (p = haystack; *p; ++p)
    {
        if (_strnicmp(p, needle, nlen) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

/* Build the path to warp-cli.exe (next to the target) into cli. Returns FALSE
   if the target has no directory component or the CLI is not present. */
static BOOL FindWarpCli(const char* target, char* cli, size_t cliSize)
{
    char dir[MAX_PATH * 2];

    GetDirName(target, dir, sizeof(dir));
    if (dir[0] == '\0')
    {
        return FALSE;
    }

    _snprintf(cli, cliSize, "%s\\warp-cli.exe", dir);
    cli[cliSize - 1] = '\0';

    return FileExists(cli);
}

/* If WARP is Connected, disconnect it before we stop/patch the service.
   warp-cli.exe is expected in the same directory as the target. Sets
   *outWasConnected to TRUE if WARP was connected (so the caller can reconnect
   afterward). Best-effort: a missing CLI or a query we cannot parse is logged
   and treated as success so patching still proceeds. */
BOOL WarpDisconnectIfConnected(const char* target, BOOL* outWasConnected)
{
    char cli[MAX_PATH * 2];
    char cmd[MAX_PATH * 4];
    char output[4096];
    DWORD exitCode = 0;

    if (outWasConnected)
    {
        *outWasConnected = FALSE;
    }

    if (!FindWarpCli(target, cli, sizeof(cli)))
    {
        UiLog("[*] warp-cli.exe not found next to the target; skipping status check.");
        return TRUE;
    }

    _snprintf(cmd, sizeof(cmd), "\"%s\" status", cli);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!RunAndCapture(cmd, NULL, output, sizeof(output), &exitCode))
    {
        UiLog("[!] Could not run 'warp-cli status' (error %lu); continuing.",
              GetLastError());
        return TRUE;
    }

    if (!ContainsNoCase(output, "Connected"))
    {
        UiLog("[*] WARP is not connected.");
        return TRUE;
    }

    if (outWasConnected)
    {
        *outWasConnected = TRUE;
    }

    UiLog("[*] WARP reports Connected; disconnecting before patch.");
    _snprintf(cmd, sizeof(cmd), "\"%s\" disconnect", cli);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!RunAndCapture(cmd, NULL, output, sizeof(output), &exitCode))
    {
        UiLog("[!] Failed to run 'warp-cli disconnect' (error %lu); continuing.",
              GetLastError());
        return TRUE;
    }

    UiLog("[+] Disconnected WARP.");
    return TRUE;
}

/* Reconnect WARP after patching. warp-cli.exe is expected next to the target.
   Best-effort: a missing CLI or a failure is logged but not fatal. */
BOOL WarpConnect(const char* target)
{
    char cli[MAX_PATH * 2];
    char cmd[MAX_PATH * 4];
    char output[4096];
    DWORD exitCode = 0;

    if (!FindWarpCli(target, cli, sizeof(cli)))
    {
        UiLog("[*] warp-cli.exe not found next to the target; skipping reconnect.");
        return TRUE;
    }

    UiLog("[*] Reconnecting WARP.");
    _snprintf(cmd, sizeof(cmd), "\"%s\" connect", cli);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!RunAndCapture(cmd, NULL, output, sizeof(output), &exitCode))
    {
        UiLog("[!] Failed to run 'warp-cli connect' (error %lu).", GetLastError());
        return FALSE;
    }

    UiLog("[+] Reconnected WARP.");
    return TRUE;
}

/* Restore the original binary from its backup. Returns TRUE on success. */
BOOL RunRestore(const char* target)
{
    char backup[MAX_PATH * 2];
    unsigned char* data;
    size_t size;

    BuildBackupPath(target, backup, sizeof(backup));

    if (!FileExists(backup))
    {
        UiLog("[!] No backup found at '%s'. Nothing to restore.", backup);
        return FALSE;
    }

    data = ReadWholeFile(backup, &size);
    if (!data)
    {
        return FALSE;
    }

    /* Guard against a stale backup: if the current binary is a different size,
       WARP was updated after the backup was taken, and restoring would downgrade
       it to the old version. The fresh binary is already unpatched, so there is
       nothing to restore -- tell the user to delete the stale backup instead. */
    if (FileExists(target))
    {
        size_t targetSize = 0;
        unsigned char* cur = ReadWholeFile(target, &targetSize);
        if (cur)
        {
            free(cur);
            if (targetSize != size)
            {
                UiLog("[!] Backup size (%zu) does not match the current binary (%zu).",
                      size, targetSize);
                UiLog("    The backup is stale (likely from a previous WARP version).");
                UiLog("    The current binary is already unpatched; delete %s.", backup);
                free(data);
                return FALSE;
            }
        }
    }

    if (!WriteWholeFile(target, data, size))
    {
        free(data);
        return FALSE;
    }

    free(data);
    UiLog("[+] Restored original binary.");
    return TRUE;
}

/* Patch the target's MASQUE SNI to newSni. Returns TRUE on success. */
BOOL RunPatch(const char* target, const char* newSni)
{
    char backup[MAX_PATH * 2];
    unsigned char* source = NULL;
    size_t sourceSize = 0;
    size_t targetSize = 0;
    PE_VIEW view;
    OCCURRENCE occs[MAX_OCCURRENCES];
    size_t occCount;
    size_t newLen;
    size_t minHostLen;
    size_t i;
    DWORD lenFieldsPatched;
    DWORD codeImmsPatched;

    /* Determine the shortest known hostname; the new SNI must fit in place. */
    minHostLen = (size_t)-1;
    for (i = 0; i < sizeof(g_KnownHostnames) / sizeof(g_KnownHostnames[0]); ++i)
    {
        if (g_KnownHostnames[i].length < minHostLen)
        {
            minHostLen = g_KnownHostnames[i].length;
        }
    }

    newLen = strlen(newSni);
    if (newLen == 0)
    {
        UiLog("[!] New SNI must not be empty.");
        return FALSE;
    }
    if (newLen > minHostLen)
    {
        UiLog("[!] New SNI '%s' is %zu bytes; max is %zu (in-place limit).",
              newSni, newLen, minHostLen);
        return FALSE;
    }

    if (!FileExists(target))
    {
        UiLog("[!] Target not found: %s", target);
        UiLog("    Check the WARP service path field.");
        return FALSE;
    }

    BuildBackupPath(target, backup, sizeof(backup));

    /* Decide the pristine source by INSPECTING the target, not by blindly
       trusting an existing backup. Our patch never changes the file size and a
       pristine binary still contains the full MASQUE hostnames, so:
         - target still has the hostnames  -> it is pristine (fresh install or a
           fresh WARP update). Refresh the backup from it, patch it.
         - target has none                 -> it is already patched. Fall back to
           the backup, but only if the backup is pristine AND the same size as the
           current target (a size mismatch means the backup is stale, i.e. from a
           previous WARP version, and using it would downgrade the binary). */
    {
        unsigned char* targetBuf;
        PE_VIEW targetView;
        size_t targetOcc;

        targetBuf = ReadWholeFile(target, &targetSize);
        if (!targetBuf)
        {
            return FALSE;
        }
        if (!ParsePe(targetBuf, targetSize, &targetView))
        {
            free(targetBuf);
            return FALSE;
        }
        targetOcc = CollectOccurrences(&targetView, occs, MAX_OCCURRENCES);

        if (targetOcc > 0)
        {
            /* Pristine target -> (re)create the backup from it. */
            if (!WriteWholeFile(backup, targetBuf, targetSize))
            {
                free(targetBuf);
                return FALSE;
            }
            source = targetBuf;
            sourceSize = targetSize;
            view = targetView;
            occCount = targetOcc;
        }
        else
        {
            /* Already-patched target -> need the backup as the pristine source. */
            free(targetBuf);

            if (!FileExists(backup))
            {
                UiLog("[!] No known MASQUE hostnames in the target and no backup exists.");
                UiLog("    It may already be patched with no backup, or WARP changed its hostnames.");
                return FALSE;
            }

            source = ReadWholeFile(backup, &sourceSize);
            if (!source)
            {
                return FALSE;
            }

            if (sourceSize != targetSize)
            {
                UiLog("[!] Backup size (%zu) does not match the current binary (%zu).",
                      sourceSize, targetSize);
                UiLog("    The backup is stale (likely from a previous WARP version).");
                UiLog("    Delete %s and re-run against the fresh binary.", backup);
                free(source);
                return FALSE;
            }

            if (!ParsePe(source, sourceSize, &view))
            {
                free(source);
                return FALSE;
            }
            occCount = CollectOccurrences(&view, occs, MAX_OCCURRENCES);
            if (occCount == 0)
            {
                UiLog("[!] Backup has no known MASQUE hostnames either; cannot patch.");
                UiLog("    WARP may have changed its hostnames; the patcher needs updating.");
                free(source);
                return FALSE;
            }
        }
    }

    for (i = 0; i < occCount; ++i)
    {
        OverwriteHostname(&view, &occs[i], newSni, newLen);
    }

    lenFieldsPatched = PatchFatPointerLengths(&view, occs, occCount, newLen);
    codeImmsPatched = PatchCodeLengthImmediates(&view, occs, occCount, newLen);
    (void)lenFieldsPatched;
    (void)codeImmsPatched;

    if (!WriteWholeFile(target, view.base, view.size))
    {
        free(source);
        return FALSE;
    }

    free(source);
    UiLog("[+] Patched %s -> %s (%zu hostnames).", target, newSni, occCount);
    return TRUE;
}
