/*
 * WARP SNI Patcher -- core (PE parsing, in-place patching, service control).
 *
 * Standalone on-disk patcher for Cloudflare WARP's warp-svc.exe. It overrides
 * two groups of hostnames baked into the binary:
 *   1. MASQUE tunnel SNI hostnames (consumer-masque / zt-masque ...).
 *   2. The registration API endpoint hostname (api.cloudflareclient.com), the
 *      SNI used for the client-registration HTTPS API.
 *
 * Each string is overwritten in place, keeping its original address so no Rust
 * &'static str fat-pointer or LEA needs repointing -- only the lengths:
 *   1. Fat-pointer length fields in data ([ptr][len]) whose ptr matches.
 *   2. `mov r32, imm32` length immediates in code, only within a small window
 *      around a `lea reg,[rip+disp]` that targets the matched hostname.
 *   3. Registration hosts only: a parallel ptr/len array (next to the string
 *      "ConsumerEndpointConfig") that code indexes at runtime.
 *
 * MASQUE hostnames live in the packed Rust string table, so a replacement must
 * be no longer than the original and the old tail is left in place. The
 * registration hosts live in fixed 32-byte zero-padded slots
 * ([slot][0xFF..FF marker][ptr][len]), so a replacement may be LONGER (up to
 * the measured slot capacity) with the leftover zeroed. Every API host is
 * stored as an FQDN with a trailing dot, so one is appended when it fits.
 *
 * The original is preserved as <target>.bak, refreshed whenever the target
 * still contains ALL known hostnames (pristine install or fresh WARP update),
 * so re-running stays clean and an update never leaves a stale backup.
 *
 * NOTE: patching breaks warp-svc.exe's Authenticode signature, and WARP updates
 * replace the binary, so the patcher must be re-run after each update.
 */

#include "patcher.h"
#include <ctype.h>
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
    BOOL patchTarget;   /* TRUE: replace this string; FALSE: anchor only */
} KNOWN_SNI;

/* MASQUE tunnel hostnames: packed string-table literals, so a replacement must
   fit the original length and the tail is left intact (see OverwriteHostname). */
static const KNOWN_SNI g_MasqueHostnames[] = {
    { "consumer-masque.cloudflareclient.com", 36, TRUE },
    { "consumer-masque.cloudflareclient.com.", 37, TRUE },
    { "consumer-masque-proxy.cloudflareclient.com", 42, TRUE },
    { "consumer-masque-proxy.cloudflareclient.com.", 43, TRUE },
    { "zt-masque.cloudflareclient.com", 30, TRUE },
    { "zt-masque.cloudflareclient.com.", 31, TRUE },
    { "zt-masque-proxy.cloudflareclient.com", 36, TRUE },
    { "zt-masque-proxy.cloudflareclient.com.", 37, TRUE }
};

/* Registration API hosts: trailing-dot FQDNs in fixed 32-byte slots, so a
   replacement may grow up to the slot capacity. Only the consumer endpoint is
   a patch target; the devices/federal anchors let PatchSoaLengths find and
   verify the parallel ptr/len arrays first. Undotted forms are accepted too. */
static const KNOWN_SNI g_RegHostnames[] = {
    { "api.cloudflareclient.com.", 25, TRUE },
    { "api.cloudflareclient.com", 24, TRUE },
    { "api.devices.cloudflare.com.", 27, FALSE },
    { "api.devices.cloudflare.com", 26, FALSE },
    { "api.devices.fed.cloudflare.com.", 31, FALSE },
    { "api.devices.fed.cloudflare.com", 30, FALSE }
};

#define MASQUE_HOSTNAME_COUNT \
    (sizeof(g_MasqueHostnames) / sizeof(g_MasqueHostnames[0]))
#define REG_HOSTNAME_COUNT \
    (sizeof(g_RegHostnames) / sizeof(g_RegHostnames[0]))

/* A located hostname occurrence in the on-disk image. */
typedef struct OCCURRENCE_TAG
{
    size_t fileOffset;      /* byte offset within the file buffer */
    ULONGLONG virtualAddr;  /* preferred VA = ImageBase + RVA */
    size_t originalLength;  /* length of the matched hostname */
    const KNOWN_SNI* known; /* table entry that matched here */
    BOOL slotConfirmed;     /* fixed-slot storage layout verified */
    size_t slotCapacity;    /* usable bytes at fileOffset when confirmed */
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
        UiLog(Tr(STR_LOG_ERR_OPEN_FILE), path);
        return NULL;
    }

    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > (LONGLONG)0x7FFFFFFF)
    {
        UiLog(Tr(STR_LOG_ERR_INVALID_SIZE), path);
        CloseHandle(file);
        return NULL;
    }

    buffer = (unsigned char*)malloc((size_t)fileSize.QuadPart);
    if (!buffer)
    {
        UiLog(Tr(STR_LOG_ERR_NOT_ENOUGH_MEM), path);
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
            UiLog(Tr(STR_LOG_ERR_READ_FILE), path);
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
        UiLog(Tr(STR_LOG_ERR_SAVE_CHANGES_ADMIN), path);
        return FALSE;
    }

    while (total < size)
    {
        DWORD chunk = (size - total > 0x10000000) ? 0x10000000 : (DWORD)(size - total);
        if (!WriteFile(file, data + total, chunk, &written, NULL))
        {
            UiLog(Tr(STR_LOG_ERR_WRITE_FILE), path);
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
        UiLog("%s", Tr(STR_LOG_ERR_FILE_TOO_SMALL));
        return FALSE;
    }

    dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        UiLog("%s", Tr(STR_LOG_ERR_NOT_VALID_PE));
        return FALSE;
    }

    if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size)
    {
        UiLog("%s", Tr(STR_LOG_ERR_PE_HEADER_INVALID));
        return FALSE;
    }

    nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        UiLog("%s", Tr(STR_LOG_ERR_NOT_VALID_PE));
        return FALSE;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        UiLog("%s", Tr(STR_LOG_ERR_X64_ONLY));
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

/* Measure usable bytes in a registration slot laid out as
   [string][zero pad][0xFF..FF marker][ptr=self][len]. Walk qwords to the
   marker, requiring zero padding and a valid self fat-pointer after it; set
   *outCapacity to the marker distance. FALSE if the layout doesn't match (the
   caller then limits the replacement to the original length). */
static BOOL MeasureRegSlot(
    const PE_VIEW* view,
    const OCCURRENCE* occ,
    size_t* outCapacity)
{
    const size_t maxQwords = 8;   /* examine up to 64 bytes past the string */
    size_t q = (occ->originalLength + 7) / 8;
    size_t i;

    for (; q < maxQwords; ++q)
    {
        size_t pos = occ->fileOffset + q * 8;
        ULONGLONG word;

        if (pos + 24 > view->size ||
            pos + 24 < pos)
        {
            return FALSE;
        }

        memcpy(&word, view->base + pos, sizeof(word));
        if (word != (ULONGLONG)-1)
        {
            continue;
        }

        /* Everything between the string end and the marker must be padding. */
        for (i = occ->originalLength; i < q * 8; ++i)
        {
            if (view->base[occ->fileOffset + i] != 0)
            {
                return FALSE;
            }
        }

        /* The marker must be followed by [ptr=self][len=originalLength]. */
        memcpy(&word, view->base + pos + 8, sizeof(word));
        if (word != occ->virtualAddr)
        {
            return FALSE;
        }
        memcpy(&word, view->base + pos + 16, sizeof(word));
        if (word != (ULONGLONG)occ->originalLength)
        {
            return FALSE;
        }

        *outCapacity = q * 8;
        return TRUE;
    }

    return FALSE;
}

/* Locate every occurrence of the given hostnames in data sections. When
   measureSlots is set (registration family), measure each slot's capacity so a
   longer replacement can be allowed. */
static size_t CollectOccurrences(
    const PE_VIEW* view,
    const KNOWN_SNI* list,
    size_t listCount,
    BOOL measureSlots,
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
            for (hi = 0; hi < listCount; ++hi)
            {
                const KNOWN_SNI* known = &list[hi];
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
                out[count].known = best;
                out[count].slotConfirmed = FALSE;
                out[count].slotCapacity = best->length;
                if (measureSlots)
                {
                    out[count].slotConfirmed =
                        MeasureRegSlot(view, &out[count], &out[count].slotCapacity);
                }
                count++;
                /* Skip past this occurrence to avoid a prefix re-match inside it. */
                off += best->length - 1;
            }
        }
    }

    return count;
}

/* Overwrite the hostname in place with the new value. In a confirmed fixed slot
   the rest is zeroed (the runtime reads only (ptr, len)). For packed
   string-table literals the tail is left intact: with no NUL terminator the
   patched length bounds every read, and a linker tail-merged suffix (e.g. a
   shared "cloudflareclient.com") stays valid. */
static void OverwriteHostname(
    PE_VIEW* view,
    const OCCURRENCE* occ,
    const char* newSni,
    size_t newLen)
{
    unsigned char* dst = view->base + occ->fileOffset;
    memcpy(dst, newSni, newLen);
    if (occ->slotConfirmed)
    {
        memset(dst + newLen, 0, occ->slotCapacity - newLen);
    }
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
                if (!occs[oi].known->patchTarget)
                {
                    continue;
                }
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

/* Find the occurrence whose hostname lives at the given VA, or NULL. */
static const OCCURRENCE* FindOccurrenceByVa(
    const OCCURRENCE* occs,
    size_t occCount,
    ULONGLONG va)
{
    size_t oi;
    for (oi = 0; oi < occCount; ++oi)
    {
        if (occs[oi].virtualAddr == va)
        {
            return &occs[oi];
        }
    }
    return NULL;
}

/* Registration hosts also live in two parallel arrays -- [len..][ptr..] -- that
   code indexes at runtime. Rewrite the len paired with each patched host, but
   only after verifying the whole ptr run is known reg hostnames and every len
   matches its hostname's real length, so unrelated arrays never match. */
static DWORD PatchSoaLengths(
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

        /* Scan on qword alignment; the arrays are compiler-emitted and
           always aligned. */
        for (off = 0; off + sizeof(ULONGLONG) <= secSize; )
        {
            ULONGLONG word;
            size_t runStart;
            size_t runEnd;
            size_t runCount;
            size_t lenBase;

            memcpy(&word, secBase + off, sizeof(word));
            if (!FindOccurrenceByVa(occs, occCount, word))
            {
                off += sizeof(ULONGLONG);
                continue;
            }

            /* Expand to the full run of hostname-VA qwords around this hit. */
            runStart = off;
            while (runStart >= sizeof(ULONGLONG) &&
                   runStart - sizeof(ULONGLONG) + sizeof(ULONGLONG) <= secSize)
            {
                ULONGLONG prev;
                memcpy(&prev, secBase + runStart - sizeof(ULONGLONG), sizeof(prev));
                if (!FindOccurrenceByVa(occs, occCount, prev))
                {
                    break;
                }
                runStart -= sizeof(ULONGLONG);
            }
            runEnd = off + sizeof(ULONGLONG);
            while (runEnd + sizeof(ULONGLONG) <= secSize)
            {
                ULONGLONG next;
                memcpy(&next, secBase + runEnd, sizeof(next));
                if (!FindOccurrenceByVa(occs, occCount, next))
                {
                    break;
                }
                runEnd += sizeof(ULONGLONG);
            }

            runCount = (runEnd - runStart) / sizeof(ULONGLONG);
            lenBase = runStart - runCount * sizeof(ULONGLONG);

            if (runCount >= 2 &&
                lenBase < runStart &&
                runEnd <= secSize)
            {
                /* Verify the parallel len array pairs up with the ptr array. */
                BOOL allMatch = TRUE;
                size_t i;

                for (i = 0; i < runCount; ++i)
                {
                    ULONGLONG ptr;
                    ULONGLONG len;
                    const OCCURRENCE* occ;

                    memcpy(&ptr, secBase + runStart + i * sizeof(ULONGLONG), sizeof(ptr));
                    memcpy(&len, secBase + lenBase + i * sizeof(ULONGLONG), sizeof(len));
                    occ = FindOccurrenceByVa(occs, occCount, ptr);
                    if (!occ || len != (ULONGLONG)occ->originalLength)
                    {
                        allMatch = FALSE;
                        break;
                    }
                }

                if (allMatch)
                {
                    for (i = 0; i < runCount; ++i)
                    {
                        ULONGLONG ptr;
                        ULONGLONG len;
                        const OCCURRENCE* occ;

                        memcpy(&ptr, secBase + runStart + i * sizeof(ULONGLONG), sizeof(ptr));
                        memcpy(&len, secBase + lenBase + i * sizeof(ULONGLONG), sizeof(len));
                        occ = FindOccurrenceByVa(occs, occCount, ptr);

                        if (occ->known->patchTarget && len != (ULONGLONG)newLen)
                        {
                            ULONGLONG newLen64 = (ULONGLONG)newLen;
                            memcpy(secBase + lenBase + i * sizeof(ULONGLONG),
                                   &newLen64, sizeof(newLen64));
                            patched++;
                        }
                    }
                }
            }

            off = runEnd;
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
                if (occs[oi].known->patchTarget &&
                    targetVa == occs[oi].virtualAddr)
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
        UiLog("%s", Tr(STR_LOG_ERR_SCM_ADMIN));
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
        UiLog("%s", Tr(STR_LOG_ERR_ACCESS_SERVICE));
        return FALSE;
    }

    if (!QueryServiceStatus(svc, &status))
    {
        UiLog("%s", Tr(STR_LOG_ERR_CHECK_SERVICE_STATUS));
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

    UiLog("%s", Tr(STR_LOG_STOP_SERVICE));
    if (status.dwCurrentState != SERVICE_STOP_PENDING)
    {
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &status))
        {
            UiLog("%s", Tr(STR_LOG_ERR_STOP_SERVICE));
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
        UiLog("%s", Tr(STR_LOG_ERR_STOP_TIMEOUT));
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
        UiLog("%s", Tr(STR_LOG_ERR_SCM_ADMIN));
        return FALSE;
    }

    svc = OpenServiceA(scm, WARP_SERVICE_NAME,
                       SERVICE_QUERY_STATUS | SERVICE_START);
    if (!svc)
    {
        UiLog("%s", Tr(STR_LOG_ERR_OPEN_SERVICE_START));
        CloseServiceHandle(scm);
        return FALSE;
    }

    UiLog("%s", Tr(STR_LOG_START_SERVICE));
    if (!StartServiceA(svc, 0, NULL))
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING)
        {
            UiLog("%s", Tr(STR_LOG_ERR_START_SERVICE));
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
        UiLog("%s", Tr(STR_LOG_ERR_START_TIMEOUT));
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

    UiLog("%s", Tr(STR_LOG_CLEANING_USERENV));
    if (!DeleteFileA(dll))
    {
        UiLog(Tr(STR_LOG_ERR_DELETE_USERENV), dll);
        return FALSE;
    }

    UiLog("%s", Tr(STR_LOG_CLEANED_USERENV));
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

/* Case-insensitive whole-word substring search. */
static BOOL ContainsWordNoCase(const char* haystack, const char* needle)
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
            BOOL leftOk = (p == haystack) || !isalpha((unsigned char)*(p - 1));
            BOOL rightOk = !isalpha((unsigned char)*(p + nlen));
            if (leftOk && rightOk)
            {
                return TRUE;
            }
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

    if (outWasConnected)
    {
        *outWasConnected = TRUE;
    }

    UiLog("%s", Tr(STR_LOG_DISCONNECTING));
    _snprintf(cmd, sizeof(cmd), "\"%s\" disconnect", cli);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!RunAndCapture(cmd, NULL, output, sizeof(output), &exitCode))
    {
        return TRUE;
    }

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
        return TRUE;
    }

    _snprintf(cmd, sizeof(cmd), "\"%s\" connect", cli);
    cmd[sizeof(cmd) - 1] = '\0';

    if (!RunAndCapture(cmd, NULL, output, sizeof(output), &exitCode))
    {
        UiLog("%s", Tr(STR_LOG_RECONNECT_NOTE));
        return FALSE;
    }

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
        UiLog("%s", Tr(STR_LOG_ERR_NO_BACKUP));
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
                UiLog("%s", Tr(STR_LOG_ERR_BACKUP_DIFF_VER));
                UiLog("%s", Tr(STR_LOG_ERR_CURRENT_UNPATCHED));
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
    DeleteFileA(backup);
    UiLog("%s", Tr(STR_LOG_RESTORED_OK));
    return TRUE;
}

/* Count occurrences that are patch targets. */
static size_t CountTargets(const OCCURRENCE* occs, size_t occCount)
{
    size_t n = 0;
    size_t i;
    for (i = 0; i < occCount; ++i)
    {
        if (occs[i].known->patchTarget)
        {
            n++;
        }
    }
    return n;
}

/* Smallest length among the patch-target entries of a known-hostname list;
   the replacement must fit inside it (in-place limit). */
static size_t MinTargetLength(const KNOWN_SNI* list, size_t listCount)
{
    size_t best = (size_t)-1;
    size_t i;
    for (i = 0; i < listCount; ++i)
    {
        if (list[i].patchTarget && list[i].length < best)
        {
            best = list[i].length;
        }
    }
    return best;
}

/* Largest length that every patch-target occurrence can hold in place. */
static size_t MaxTargetCapacity(const OCCURRENCE* occs, size_t occCount)
{
    size_t best = (size_t)-1;
    size_t i;
    for (i = 0; i < occCount; ++i)
    {
        size_t cap;
        if (!occs[i].known->patchTarget)
        {
            continue;
        }
        cap = occs[i].slotConfirmed ? occs[i].slotCapacity : occs[i].originalLength;
        if (cap < best)
        {
            best = cap;
        }
    }
    return best;
}

static const char* StripTrailingDot(const char* s, char* buf, size_t bufSize)
{
    size_t len;
    if (!buf || bufSize == 0)
    {
        return s ? s : "";
    }
    if (!s)
    {
        buf[0] = '\0';
        return buf;
    }
    len = strlen(s);
    if (len > 0 && s[len - 1] == '.')
    {
        len--;
    }
    if (len >= bufSize)
    {
        len = bufSize - 1;
    }
    memcpy(buf, s, len);
    buf[len] = '\0';
    return buf;
}

/* Patch the target's MASQUE SNI and registration API hostname. Returns TRUE
   on success. */
BOOL RunPatch(const char* target, const char* newSni, const char* newRegSni)
{
    char backup[MAX_PATH * 2];
    unsigned char* source = NULL;
    size_t sourceSize = 0;
    size_t targetSize = 0;
    PE_VIEW view;
    OCCURRENCE masqueOccs[MAX_OCCURRENCES];
    OCCURRENCE regOccs[MAX_OCCURRENCES];
    size_t masqueCount = 0;
    size_t regCount = 0;
    size_t masqueTargets;
    size_t regTargets;
    size_t newLen;
    size_t minMasqueLen;
    size_t regLenPlain;
    size_t regLenDotted;
    size_t regLenFinal;
    size_t regCap;
    char regDotted[256];
    const char* regFinal;
    size_t i;
    DWORD lenFieldsPatched = 0;
    DWORD soaPatched = 0;
    DWORD codeImmsPatched = 0;
    BOOL regLenChanged;

    newLen = strlen(newSni);
    minMasqueLen = MinTargetLength(g_MasqueHostnames, MASQUE_HOSTNAME_COUNT);
    if (newLen == 0)
    {
        UiLog(Tr(STR_LOG_ERR_EMPTY_SNI), DEFAULT_SNI);
        return FALSE;
    }
    if (newLen > minMasqueLen)
    {
        UiLog(Tr(STR_LOG_ERR_SNI_TOO_LONG),
              newSni, newLen, minMasqueLen);
        UiLog(Tr(STR_LOG_TIP_DEFAULT_SNI), DEFAULT_SNI);
        return FALSE;
    }

    regLenPlain = strlen(newRegSni);
    if (regLenPlain == 0)
    {
        UiLog(Tr(STR_LOG_ERR_EMPTY_REG_SNI), DEFAULT_REG_SNI);
        return FALSE;
    }
    if (regLenPlain > sizeof(regDotted) - 2)
    {
        UiLog(Tr(STR_LOG_ERR_REG_SNI_TOO_LONG),
              sizeof(regDotted) - 2);
        UiLog(Tr(STR_LOG_TIP_DEFAULT_REG_SNI), DEFAULT_REG_SNI);
        return FALSE;
    }

    if (!FileExists(target))
    {
        UiLog(Tr(STR_LOG_ERR_FIND_WARP_SVC), target);
        UiLog("%s", Tr(STR_LOG_ERR_VERIFY_PATH));
        return FALSE;
    }

    BuildBackupPath(target, backup, sizeof(backup));

    /* Pick the pristine source by inspecting the target (patching never changes
       the size): if every family's hostnames are present it is pristine, so
       refresh the backup from it. Otherwise it is already patched -- use the
       backup, but only if it is the same size (a mismatch means a stale backup
       from an older WARP version, which would downgrade the binary). */
    {
        unsigned char* targetBuf;
        PE_VIEW targetView;
        size_t tMasque;
        size_t tReg;
        BOOL masqOk;
        BOOL regOk;

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
        tMasque = CollectOccurrences(&targetView, g_MasqueHostnames,
                                     MASQUE_HOSTNAME_COUNT, FALSE,
                                     masqueOccs, MAX_OCCURRENCES);
        tReg = CollectOccurrences(&targetView, g_RegHostnames,
                                  REG_HOSTNAME_COUNT, TRUE,
                                  regOccs, MAX_OCCURRENCES);
        masqOk = CountTargets(masqueOccs, tMasque) > 0;
        regOk = CountTargets(regOccs, tReg) > 0;

        if (masqOk && regOk)
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
            masqueCount = tMasque;
            regCount = tReg;
            UiLog("%s", Tr(STR_LOG_BACKUP));
        }
        else
        {
            /* Already-patched target -> need the backup as the pristine source. */
            free(targetBuf);

            if (!FileExists(backup))
            {
                UiLog("%s", Tr(STR_LOG_ERR_NO_ORIG_HOSTS_AND_NO_BACKUP));
                UiLog("%s", Tr(STR_LOG_ERR_ALREADY_PATCHED_OR_UNSUPPORTED));
                return FALSE;
            }

            source = ReadWholeFile(backup, &sourceSize);
            if (!source)
            {
                return FALSE;
            }

            if (sourceSize != targetSize)
            {
                UiLog("%s", Tr(STR_LOG_ERR_BACKUP_DIFF_VER));
                UiLog(Tr(STR_LOG_ERR_DELETE_BACKUP_FRESH), backup);
                free(source);
                return FALSE;
            }

            if (!ParsePe(source, sourceSize, &view))
            {
                free(source);
                return FALSE;
            }

            masqueCount = CollectOccurrences(&view, g_MasqueHostnames,
                                             MASQUE_HOSTNAME_COUNT, FALSE,
                                             masqueOccs, MAX_OCCURRENCES);
            regCount = CollectOccurrences(&view, g_RegHostnames,
                                          REG_HOSTNAME_COUNT, TRUE,
                                          regOccs, MAX_OCCURRENCES);
            if (CountTargets(masqueOccs, masqueCount) == 0 ||
                CountTargets(regOccs, regCount) == 0)
            {
                UiLog("%s", Tr(STR_LOG_ERR_BACKUP_NO_ORIG_HOSTS));
                UiLog("%s", Tr(STR_LOG_ERR_BACKUP_UNSUPPORTED));
                free(source);
                return FALSE;
            }
        }
    }

    masqueTargets = CountTargets(masqueOccs, masqueCount);
    regTargets = CountTargets(regOccs, regCount);

    /* Every API host is stored as a trailing-dot FQDN, so prefer the dotted
       form of the input; fall back to as-typed only when that alone fits. */
    if (newRegSni[regLenPlain - 1] == '.')
    {
        regLenDotted = regLenPlain;
        _snprintf(regDotted, sizeof(regDotted), "%s", newRegSni);
    }
    else
    {
        regLenDotted = regLenPlain + 1;
        _snprintf(regDotted, sizeof(regDotted), "%s.", newRegSni);
    }
    regDotted[sizeof(regDotted) - 1] = '\0';

    regCap = MaxTargetCapacity(regOccs, regCount);
    if (regLenDotted <= regCap)
    {
        regFinal = regDotted;
        regLenFinal = regLenDotted;
    }
    else if (regLenPlain <= regCap)
    {
        regFinal = newRegSni;
        regLenFinal = regLenPlain;
    }
    else
    {
        UiLog(Tr(STR_LOG_ERR_REG_HOSTNAME_TOO_LONG),
              newRegSni, regLenPlain, regCap);
        UiLog(Tr(STR_LOG_TIP_DEFAULT_REG_SNI), DEFAULT_REG_SNI);
        free(source);
        return FALSE;
    }

    /* Overwrite the hostname strings in place. */
    for (i = 0; i < masqueCount; ++i)
    {
        if (masqueOccs[i].known->patchTarget)
        {
            OverwriteHostname(&view, &masqueOccs[i], newSni, newLen);
        }
    }
    for (i = 0; i < regCount; ++i)
    {
        if (regOccs[i].known->patchTarget)
        {
            OverwriteHostname(&view, &regOccs[i], regFinal, regLenFinal);
        }
    }

    lenFieldsPatched += PatchFatPointerLengths(&view, masqueOccs, masqueCount, newLen);
    lenFieldsPatched += PatchFatPointerLengths(&view, regOccs, regCount, regLenFinal);
    soaPatched = PatchSoaLengths(&view, regOccs, regCount, regLenFinal);
    codeImmsPatched += PatchCodeLengthImmediates(&view, masqueOccs, masqueCount, newLen);
    codeImmsPatched += PatchCodeLengthImmediates(&view, regOccs, regCount, regLenFinal);

    /* If the reg length changed, the ptr/len array must have been updated, or
       the service would read a truncated hostname -- refuse to write. */
    regLenChanged = FALSE;
    for (i = 0; i < regCount; ++i)
    {
        if (regOccs[i].known->patchTarget &&
            regOccs[i].originalLength != regLenFinal)
        {
            regLenChanged = TRUE;
        }
    }
    if (regLenChanged && soaPatched == 0)
    {
        UiLog("%s", Tr(STR_LOG_ERR_REG_UPDATE_UNSAFE));
        UiLog(Tr(STR_LOG_TIP_DEFAULT_REG_SNI), DEFAULT_REG_SNI);
        free(source);
        return FALSE;
    }

    if (!WriteWholeFile(target, view.base, view.size))
    {
        free(source);
        return FALSE;
    }

    free(source);
    {
        char uniqueMasque[16][256];
        size_t uniqueMasqueCount = 0;
        char uniqueReg[16][256];
        size_t uniqueRegCount = 0;
        char cleanNewSni[256];
        char cleanNewRegSni[256];
        size_t k, u;

        memset(uniqueMasque, 0, sizeof(uniqueMasque));
        memset(uniqueReg, 0, sizeof(uniqueReg));
        memset(cleanNewSni, 0, sizeof(cleanNewSni));
        memset(cleanNewRegSni, 0, sizeof(cleanNewRegSni));

        StripTrailingDot(newSni, cleanNewSni, sizeof(cleanNewSni));
        StripTrailingDot(newRegSni, cleanNewRegSni, sizeof(cleanNewRegSni));

        /* Collect unique patched MASQUE hostnames in definition order */
        for (k = 0; k < MASQUE_HOSTNAME_COUNT; ++k)
        {
            if (!g_MasqueHostnames[k].patchTarget)
            {
                continue;
            }
            for (i = 0; i < masqueCount; ++i)
            {
                if (masqueOccs[i].known == &g_MasqueHostnames[k])
                {
                    char clean[256];
                    memset(clean, 0, sizeof(clean));
                    StripTrailingDot(g_MasqueHostnames[k].value, clean, sizeof(clean));
                    BOOL exists = FALSE;
                    for (u = 0; u < uniqueMasqueCount; ++u)
                    {
                        if (strcmp(uniqueMasque[u], clean) == 0)
                        {
                            exists = TRUE;
                            break;
                        }
                    }
                    if (!exists && uniqueMasqueCount < 16)
                    {
                        _snprintf(uniqueMasque[uniqueMasqueCount],
                                  sizeof(uniqueMasque[uniqueMasqueCount]),
                                  "%s", clean);
                        uniqueMasqueCount++;
                    }
                    break;
                }
            }
        }

        /* Collect unique patched Registration hostnames in definition order */
        for (k = 0; k < REG_HOSTNAME_COUNT; ++k)
        {
            if (!g_RegHostnames[k].patchTarget)
            {
                continue;
            }
            for (i = 0; i < regCount; ++i)
            {
                if (regOccs[i].known == &g_RegHostnames[k])
                {
                    char clean[256];
                    memset(clean, 0, sizeof(clean));
                    StripTrailingDot(g_RegHostnames[k].value, clean, sizeof(clean));
                    BOOL exists = FALSE;
                    for (u = 0; u < uniqueRegCount; ++u)
                    {
                        if (strcmp(uniqueReg[u], clean) == 0)
                        {
                            exists = TRUE;
                            break;
                        }
                    }
                    if (!exists && uniqueRegCount < 16)
                    {
                        _snprintf(uniqueReg[uniqueRegCount],
                                  sizeof(uniqueReg[uniqueRegCount]),
                                  "%s", clean);
                        uniqueRegCount++;
                    }
                    break;
                }
            }
        }

        UiLog("%s", Tr(STR_LOG_PATCHING));
        /* UiLog("MASQUE SNI:");
        if (uniqueMasqueCount > 0)
        {
            for (u = 0; u < uniqueMasqueCount; ++u)
            {
                UiLog("%s -> %s", uniqueMasque[u], cleanNewSni);
            }
        }
        else
        {
            UiLog("-> %s", cleanNewSni);
        }

        UiLog("Registration API:");
        if (uniqueRegCount > 0)
        {
            for (u = 0; u < uniqueRegCount; ++u)
            {
                UiLog("%s -> %s", uniqueReg[u], cleanNewRegSni);
            }
        }
        else
        {
            UiLog("-> %s", cleanNewRegSni);
        } */
    }
    return TRUE;
}
