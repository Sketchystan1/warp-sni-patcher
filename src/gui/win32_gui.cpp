/*
 * WARP SNI Patcher - Win32 GUI Implementation
 */

#include "gui.h"
#include "../patcher.h"
#include "../service.h"
#include "../i18n.h"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Common-Controls v6 gives buttons, scrollbars and edits the modern themed
   look. The manifest dependency is merged into the linker-embedded manifest;
   InitCommonControlsEx() is called at startup. */
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, \
    "\"/manifestdependency:type='win32' " \
    "name='Microsoft.Windows.Common-Controls' version='6.0.0.0' " \
    "processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

static std::string g_target = DEFAULT_TARGET_PATH;

/* Control IDs */
#define IDC_SNI_EDIT     1001
#define IDC_REGSNI_EDIT  1002
#define IDC_RESTORE_BTN  1003
#define IDC_PATCH_BTN    1004
#define IDC_LOG_EDIT     1005
#define IDC_LANG_BTN     1006
#define IDM_LANG_EN      2001
#define IDM_LANG_RU      2002

/* Layout constants (client-relative pixels). */
#define UI_MARGIN               16
#define UI_ROW_H                26
#define UI_BTN_H                30
#define UI_LANG_BTN_W           56
#define UI_LANG_BTN_H           24
#define UI_MIN_WIDTH            460
#define UI_COMPACT_CLIENT_H     252
#define UI_EXPANDED_CLIENT_H    396

static HWND g_hMainWindow = NULL;
static HWND g_hLog = NULL;      /* multiline log edit control */
static HFONT g_hUiFont = NULL;  /* Segoe UI, for labels/edits/buttons */
static HFONT g_hMonoFont = NULL;/* Consolas, for the log */

/* Child control handles, kept so WM_SIZE can reflow the layout. */
static HWND g_hHintLabel = NULL;
static HWND g_hSniLabel = NULL;
static HWND g_hSniEdit = NULL;
static HWND g_hRegSniLabel = NULL;
static HWND g_hRegSniEdit = NULL;
static HWND g_hRestoreBtn = NULL;
static HWND g_hPatchBtn = NULL;
static HWND g_hLangBtn = NULL;
static HWND g_hLogLabel = NULL;
static BOOL g_logVisible = FALSE;
static BOOL g_isPatched = FALSE;

static DWORD g_mainThreadId = 0;
static HANDLE g_hWorkerThread = NULL;

#define WM_APP_LOG         (WM_APP + 1)
#define WM_APP_WORKER_DONE (WM_APP + 2)

/* ---- Dark mode -------------------------------------------------------------
 * A minimal adaptation of ozone10/win32-darkmodelib: we ask Windows to allow
 * dark mode for the app via the undocumented uxtheme ordinal (SetPreferredApp-
 * Mode), darken the title bar through DWM, theme the child controls, and paint
 * the control backgrounds ourselves. The desired mode is read from the same
 * registry value the OS uses, and WM_SETTINGCHANGE re-applies it live so the
 * window follows the system light/dark setting automatically. */

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

#define DARK_BG     RGB(0x20, 0x20, 0x20)  /* window / label background */
#define DARK_CTLBG  RGB(0x2B, 0x2B, 0x2B)  /* edit / log background */
#define DARK_TEXT   RGB(0xE0, 0xE0, 0xE0)

typedef enum {
    APPMODE_DEFAULT, APPMODE_ALLOWDARK, APPMODE_FORCEDARK,
    APPMODE_FORCELIGHT, APPMODE_MAX
} PreferredAppMode;
typedef PreferredAppMode (WINAPI *SetPreferredAppMode_t)(PreferredAppMode);
typedef BOOL (WINAPI *AllowDarkModeForWindow_t)(HWND, BOOL);
typedef void (WINAPI *FlushMenuThemes_t)(void);

static AllowDarkModeForWindow_t p_AllowDarkModeForWindow = NULL;
static FlushMenuThemes_t p_FlushMenuThemes = NULL;
static BOOL g_darkMode = FALSE;
static HBRUSH g_hWndBrush = NULL;   /* DARK_BG */
static HBRUSH g_hCtlBrush = NULL;   /* DARK_CTLBG */

/* TRUE when the system asks apps to use dark mode (AppsUseLightTheme == 0). */
static BOOL ShouldUseDarkMode(void)
{
    HKEY hKey;
    DWORD value = 1, size = sizeof(value), type = 0;
    BOOL dark = FALSE;

    if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueExA(hKey, "AppsUseLightTheme", NULL, &type,
                (LPBYTE)&value, &size) == ERROR_SUCCESS && type == REG_DWORD)
        {
            dark = (value == 0);
        }
        RegCloseKey(hKey);
    }
    return dark;
}

/* One-time: opt the process into dark mode and resolve the per-window helper. */
static void InitDarkModeSupport(void)
{
    HMODULE hUx = LoadLibraryExA("uxtheme.dll", NULL,
                                 LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (hUx)
    {
        SetPreferredAppMode_t pSet = (SetPreferredAppMode_t)
            GetProcAddress(hUx, MAKEINTRESOURCEA(135));
        p_AllowDarkModeForWindow = (AllowDarkModeForWindow_t)
            GetProcAddress(hUx, MAKEINTRESOURCEA(133));
        p_FlushMenuThemes = (FlushMenuThemes_t)
            GetProcAddress(hUx, MAKEINTRESOURCEA(136));
        if (pSet)
        {
            pSet(APPMODE_ALLOWDARK);
        }
    }
    g_hWndBrush = CreateSolidBrush(DARK_BG);
    g_hCtlBrush = CreateSolidBrush(DARK_CTLBG);
}

/* Read the system setting and (re)apply light/dark to the window and controls. */
static void ApplyAppTheme(HWND hwnd)
{
    BOOL dark = ShouldUseDarkMode();
    BOOL value = dark;

    g_darkMode = dark;

    if (p_AllowDarkModeForWindow)
    {
        p_AllowDarkModeForWindow(hwnd, dark);
    }
    if (p_FlushMenuThemes)
    {
        p_FlushMenuThemes();
    }
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                          &value, sizeof(value));

    /* Text fields use the dark edit theme (DarkMode_CFD) so their border draws
       dark; the log and buttons use DarkMode_Explorer for the dark scrollbar
       and button styling. NULL resets to the default light theme. */
    {
        const wchar_t* cfd = dark ? L"DarkMode_CFD" : NULL;
        const wchar_t* exp = dark ? L"DarkMode_Explorer" : NULL;
        SetWindowTheme(g_hSniEdit, cfd, NULL);
        SetWindowTheme(g_hRegSniEdit, cfd, NULL);
        SetWindowTheme(g_hLog, exp, NULL);
        SetWindowTheme(g_hRestoreBtn, exp, NULL);
        SetWindowTheme(g_hPatchBtn, exp, NULL);
        SetWindowTheme(g_hLangBtn, exp, NULL);
    }

    InvalidateRect(hwnd, NULL, TRUE);
}

/* Create a font by face name and point size (negative height = point size). */
static HFONT MakeFont(const wchar_t* face, int pointSize, int weight)
{
    HDC hdc = GetDC(NULL);
    int height = -MulDiv(pointSize, GetDeviceCaps(hdc, LOGPIXELSY), 72);
    HFONT font;
    ReleaseDC(NULL, hdc);

    font = CreateFontW(
        height, 0, 0, 0, weight, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
    return font ? font : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
}

static void LayoutControls(HWND hwnd);

static int MeasureHintHeight(HWND hwnd, int hintW)
{
    int hintH = 48;
    if (g_hHintLabel && g_hUiFont && hintW > 0)
    {
        int textLen = GetWindowTextLengthW(g_hHintLabel);
        if (textLen > 0)
        {
            wchar_t* text = (wchar_t*)malloc((textLen + 1) * sizeof(wchar_t));
            if (text)
            {
                GetWindowTextW(g_hHintLabel, text, textLen + 1);
                HDC hdc = GetDC(hwnd);
                if (hdc)
                {
                    HFONT oldFont = (HFONT)SelectObject(hdc, g_hUiFont);
                    RECT rcText = { 0, 0, hintW, 0 };
                    DrawTextW(hdc, text, -1, &rcText, DT_CALCRECT | DT_WORDBREAK);
                    SelectObject(hdc, oldFont);
                    ReleaseDC(hwnd, hdc);
                    int calcH = (rcText.bottom - rcText.top) + 2;
                    if (calcH > 28)
                    {
                        hintH = calcH;
                    }
                }
                free(text);
            }
        }
    }
    return hintH;
}

static int GetCompactContentHeight(HWND hwnd, int hintW)
{
    int hintH = MeasureHintHeight(hwnd, hintW);
    int m = UI_MARGIN;
    int belowHint = 10 + 22 + UI_ROW_H + 12 + 22 + UI_ROW_H + 16 + UI_BTN_H + m;
    return m + hintH + belowHint;
}

/* Automatically resize window to fit current content vertically. */
static void AutoResizeToFitContent(HWND hwnd)
{
    if (!hwnd || IsIconic(hwnd) || IsZoomed(hwnd))
    {
        return;
    }

    RECT rcClient, rcWin;
    GetClientRect(hwnd, &rcClient);
    GetWindowRect(hwnd, &rcWin);

    int cw = rcClient.right - rcClient.left;
    if (cw <= 0)
    {
        cw = 500;
    }

    int fieldW = cw - UI_MARGIN * 2;
    int hintW = fieldW - UI_LANG_BTN_W - 8;
    if (hintW < 80)
    {
        hintW = 80;
    }

    int compactH = GetCompactContentHeight(hwnd, hintW);
    int targetClientH;

    if (g_logVisible)
    {
        int curClientH = rcClient.bottom - rcClient.top;
        int logTop = compactH + 22;
        int curLogH = curClientH - logTop - UI_MARGIN;
        int minLogH = 140;
        int logH = (curLogH > minLogH) ? curLogH : minLogH;
        targetClientH = logTop + logH + UI_MARGIN;
    }
    else
    {
        targetClientH = compactH;
    }

    int curClientH = rcClient.bottom - rcClient.top;
    int diffH = targetClientH - curClientH;

    if (diffH != 0)
    {
        int newWinH = (rcWin.bottom - rcWin.top) + diffH;
        int newWinW = rcWin.right - rcWin.left;
        int newTop = rcWin.top;

        RECT work;
        if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0))
        {
            if (newTop + newWinH > work.bottom)
            {
                newTop = work.bottom - newWinH;
                if (newTop < work.top)
                {
                    newTop = work.top;
                }
            }
        }

        SetWindowPos(hwnd, NULL, rcWin.left, newTop, newWinW, newWinH,
                     SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

/* Expand the window to show the log box when patching/restoring starts. */
static void EnsureLogVisible(HWND hwnd)
{
    if (g_logVisible || !hwnd)
    {
        return;
    }

    g_logVisible = TRUE;
    AutoResizeToFitContent(hwnd);

    if (g_hLogLabel) ShowWindow(g_hLogLabel, SW_SHOW);
    if (g_hLog) ShowWindow(g_hLog, SW_SHOW);
    LayoutControls(hwnd);
    InvalidateRect(hwnd, NULL, TRUE);
    UpdateWindow(hwnd);
}

static void AppendLogText(const char* line)
{
    if (!g_logVisible && g_hMainWindow)
    {
        EnsureLogVisible(g_hMainWindow);
    }

    if (g_hLog && line)
    {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, line, -1, NULL, 0);
        if (wlen > 0)
        {
            wchar_t* wline = (wchar_t*)malloc(wlen * sizeof(wchar_t));
            if (wline)
            {
                MultiByteToWideChar(CP_UTF8, 0, line, -1, wline, wlen);
                int len = GetWindowTextLengthW(g_hLog);
                SendMessageW(g_hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
                SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)wline);
                SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
                free(wline);
            }
        }
    }
}

// All backends use the same logger; marshal GUI updates to the UI thread.
static void GuiLog(const char* text, void*) {
    std::string line = TranslateLogMessage(text);
    line += "\r\n";
    if (GetCurrentThreadId() == g_mainThreadId) {
        AppendLogText(line.c_str());
    } else {
        char* copy = _strdup(line.c_str());
        if (copy && !PostMessageW(g_hMainWindow, WM_APP_LOG, 0, (LPARAM)copy)) free(copy);
    }
}

static void GetEditText(HWND parent, int id, char* buf, int bufSize)
{
    GetWindowTextA(GetDlgItem(parent, id), buf, bufSize);
}

/* Strip leading/trailing spaces and tabs in place. */
static void TrimInPlace(char* s)
{
    char* start = s;
    char* end;

    while (*start == ' ' || *start == '\t')
    {
        start++;
    }

    end = start + strlen(start);
    while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
    {
        end--;
    }
    *end = '\0';

    if (start != s)
    {
        memmove(s, start, (size_t)(end - start) + 1);
    }
}

/* Show the Restore button only when a backup file exists. */
static void UpdateRestoreButton(HWND hwnd)
{
    char backup[MAX_PATH * 2];
    BOOL show = FALSE;

    (void)hwnd;
    if (g_hRestoreBtn)
    {
        BuildBackupPath(g_target.c_str(), backup, sizeof(backup));
        show = FileExists(backup);
        ShowWindow(g_hRestoreBtn, show ? SW_SHOW : SW_HIDE);
    }
}

typedef struct {
    char target[MAX_PATH * 2];
    char sni[256];
    char regSni[256];
    BOOL isRestore;
} WORKER_PARAMS;

static void SetUiBusy(BOOL busy, BOOL isRestore)
{
    if (g_hPatchBtn)
    {
        EnableWindow(g_hPatchBtn, !busy);
        if (busy && !isRestore)
        {
            SetWindowTextW(g_hPatchBtn, TrW(STR_STATUS_PATCHING));
        }
    }
    if (g_hRestoreBtn)
    {
        EnableWindow(g_hRestoreBtn, !busy);
        if (busy && isRestore)
        {
            SetWindowTextW(g_hRestoreBtn, TrW(STR_STATUS_RESTORING));
        }
    }
    if (g_hSniEdit)
    {
        EnableWindow(g_hSniEdit, !busy);
    }
    if (g_hRegSniEdit)
    {
        EnableWindow(g_hRegSniEdit, !busy);
    }
    if (g_hLangBtn)
    {
        EnableWindow(g_hLangBtn, !busy);
    }
}

static DWORD WINAPI PatchWorkerThread(LPVOID lpParam) {
    WORKER_PARAMS* p = static_cast<WORKER_PARAMS*>(lpParam);
    warp::PatchOptions options;
    options.target_path = p->target;
    if (p->sni[0]) options.masque_host = p->sni;
    if (p->regSni[0]) options.reg_api_host = p->regSni;
    const bool success = warp::RunOperation(options, p->isRestore != FALSE);
    if (!success) UiLog("%s", Tr(p->isRestore ? STR_LOG_ERR_RESTORE_FAILED : STR_LOG_ERR_PATCH_FAILED));
    PostMessageW(g_hMainWindow, WM_APP_WORKER_DONE, (WPARAM)p->isRestore, (LPARAM)success);
    free(p);
    return 0;
}

static void OnPatchClicked(HWND hwnd)
{
    if (g_hWorkerThread != NULL)
    {
        return;
    }

    const char* target = g_target.c_str();
    char sni[256];
    char regSni[256];
    WORKER_PARAMS* p;

    EnsureLogVisible(hwnd);
    if (g_hLog)
    {
        SetWindowTextW(g_hLog, L"");
    }

    GetEditText(hwnd, IDC_SNI_EDIT, sni, sizeof(sni));
    GetEditText(hwnd, IDC_REGSNI_EDIT, regSni, sizeof(regSni));
    TrimInPlace(sni);
    TrimInPlace(regSni);

    if (!FileExists(target))
    {
        UiLog("%s", Tr(STR_LOG_ERR_TARGET_NOT_FOUND));
        UiLog("    %s", target);
        UiLog("%s", Tr(STR_LOG_ERR_CHECK_INSTALL));
        return;
    }

    p = (WORKER_PARAMS*)malloc(sizeof(WORKER_PARAMS));
    if (!p)
    {
        UiLog("%s", Tr(STR_LOG_ERR_MEM_ALLOC));
        return;
    }

    strncpy(p->target, target, sizeof(p->target) - 1);
    p->target[sizeof(p->target) - 1] = '\0';
    strncpy(p->sni, sni, sizeof(p->sni) - 1);
    p->sni[sizeof(p->sni) - 1] = '\0';
    strncpy(p->regSni, regSni, sizeof(p->regSni) - 1);
    p->regSni[sizeof(p->regSni) - 1] = '\0';
    p->isRestore = FALSE;

    SetUiBusy(TRUE, FALSE);

    g_hWorkerThread = CreateThread(NULL, 0, PatchWorkerThread, p, 0, NULL);
    if (!g_hWorkerThread)
    {
        UiLog("%s", Tr(STR_LOG_ERR_THREAD_CREATE));
        SetUiBusy(FALSE, FALSE);
        free(p);
    }
}

static void OnRestoreClicked(HWND hwnd)
{
    if (g_hWorkerThread != NULL)
    {
        return;
    }

    const char* target = g_target.c_str();
    char backup[MAX_PATH * 2];
    WORKER_PARAMS* p;

    EnsureLogVisible(hwnd);
    if (g_hLog)
    {
        SetWindowTextW(g_hLog, L"");
    }

    BuildBackupPath(target, backup, sizeof(backup));
    if (!FileExists(backup))
    {
        UiLog("%s", Tr(STR_LOG_ERR_NO_BACKUP));
        UpdateRestoreButton(hwnd);
        return;
    }

    p = (WORKER_PARAMS*)malloc(sizeof(WORKER_PARAMS));
    if (!p)
    {
        UiLog("%s", Tr(STR_LOG_ERR_MEM_ALLOC));
        return;
    }

    strncpy(p->target, target, sizeof(p->target) - 1);
    p->target[sizeof(p->target) - 1] = '\0';
    p->sni[0] = '\0';
    p->regSni[0] = '\0';
    p->isRestore = TRUE;

    SetUiBusy(TRUE, TRUE);

    g_hWorkerThread = CreateThread(NULL, 0, PatchWorkerThread, p, 0, NULL);
    if (!g_hWorkerThread)
    {
        UiLog("%s", Tr(STR_LOG_ERR_THREAD_CREATE));
        SetUiBusy(FALSE, TRUE);
        free(p);
    }
}

static HWND CreateLabel(HWND parent, const wchar_t* text, int x, int y, int w, int h)
{
    HWND label = CreateWindowExW(
        0, L"STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
        x, y, w, h, parent, NULL, NULL, NULL);
    SendMessageW(label, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);
    return label;
}

/* Reposition every control for the current client size. Called on create and
   on every WM_SIZE so the window is fully resizable: the fields, buttons and
   log stretch horizontally and the log grows to fill the remaining height. */
static void LayoutControls(HWND hwnd)
{
    RECT rc;
    int m = UI_MARGIN;
    int cw, fieldW, y, logTop;
    const int btnW = 130;
    const int gap = 8;
    const int langBtnW = UI_LANG_BTN_W;
    const int langBtnH = UI_LANG_BTN_H;
    int hintH;
    int hintW;

    GetClientRect(hwnd, &rc);
    cw = rc.right - rc.left;
    fieldW = cw - m * 2;
    if (fieldW < 120)
    {
        fieldW = 120;
    }
    hintW = fieldW - langBtnW - 8;
    if (hintW < 80)
    {
        hintW = 80;
    }
    hintH = MeasureHintHeight(hwnd, hintW);
    y = m;

    MoveWindow(g_hHintLabel, m, y, hintW, hintH, TRUE);
    if (g_hLangBtn)
    {
        MoveWindow(g_hLangBtn, m + fieldW - langBtnW, y, langBtnW, langBtnH, TRUE);
    }
    y += hintH + 10;

    MoveWindow(g_hSniLabel, m, y, fieldW, 18, TRUE);
    y += 22;
    MoveWindow(g_hSniEdit, m, y, fieldW, UI_ROW_H, TRUE);
    y += UI_ROW_H + 12;

    MoveWindow(g_hRegSniLabel, m, y, fieldW, 18, TRUE);
    y += 22;
    MoveWindow(g_hRegSniEdit, m, y, fieldW, UI_ROW_H, TRUE);
    y += UI_ROW_H + 16;

    MoveWindow(g_hRestoreBtn, m + fieldW - btnW - gap - btnW, y, btnW, UI_BTN_H, TRUE);
    MoveWindow(g_hPatchBtn, m + fieldW - btnW, y, btnW, UI_BTN_H, TRUE);
    y += UI_BTN_H + 16;

    if (g_logVisible)
    {
        ShowWindow(g_hLogLabel, SW_SHOW);
        ShowWindow(g_hLog, SW_SHOW);
        MoveWindow(g_hLogLabel, m, y, fieldW, 18, TRUE);
        y += 22;
        logTop = y;
        MoveWindow(g_hLog, m, logTop, fieldW, rc.bottom - logTop - m, TRUE);
    }
    else
    {
        ShowWindow(g_hLogLabel, SW_HIDE);
        ShowWindow(g_hLog, SW_HIDE);
    }
}

static void UpdateUiLanguage(HWND hwnd)
{
    SetWindowTextW(hwnd, TrW(STR_APP_TITLE));
    if (g_hHintLabel)
    {
        SetWindowTextW(g_hHintLabel, TrW(STR_TIP_HINT));
    }
    if (g_hSniLabel)
    {
        SetWindowTextW(g_hSniLabel, TrW(STR_MASQUE_SNI_LABEL));
    }
    if (g_hRegSniLabel)
    {
        SetWindowTextW(g_hRegSniLabel, TrW(STR_REG_SNI_LABEL));
    }
    if (g_hRestoreBtn)
    {
        SetWindowTextW(g_hRestoreBtn, TrW(STR_RESTORE_BTN));
    }
    if (g_hPatchBtn)
    {
        SetWindowTextW(g_hPatchBtn, g_isPatched ? TrW(STR_STATUS_PATCHED) : TrW(STR_PATCH_BTN));
    }
    if (g_hLogLabel)
    {
        SetWindowTextW(g_hLogLabel, TrW(STR_LOG_LABEL));
    }
    if (g_hLangBtn)
    {
        SetWindowTextW(g_hLangBtn, I18nIsRussian() ? L"РУ \x25BE" : L"EN \x25BE");
    }

    AutoResizeToFitContent(hwnd);
    LayoutControls(hwnd);
    InvalidateRect(hwnd, NULL, TRUE);
}

static void CreateControls(HWND hwnd)
{
    /* Fonts: Segoe UI for the UI, Consolas for the log. */
    g_hUiFont = MakeFont(L"Segoe UI", 10, FW_NORMAL);
    g_hMonoFont = MakeFont(L"Consolas", 10, FW_NORMAL);

    g_hHintLabel = CreateLabel(
        hwnd,
        TrW(STR_TIP_HINT),
        0, 0, 10, 32);

    g_hLangBtn = CreateWindowExW(
        0, L"BUTTON", I18nIsRussian() ? L"РУ \x25BE" : L"EN \x25BE",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        0, 0, UI_LANG_BTN_W, UI_LANG_BTN_H, hwnd, (HMENU)(INT_PTR)IDC_LANG_BTN, NULL, NULL);
    SendMessageW(g_hLangBtn, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);

    g_hSniLabel = CreateLabel(hwnd, TrW(STR_MASQUE_SNI_LABEL), 0, 0, 10, 18);
    g_hSniEdit = CreateWindowExW(
        0, L"EDIT", L"" DEFAULT_SNI,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL,
        0, 0, 10, UI_ROW_H, hwnd, (HMENU)(INT_PTR)IDC_SNI_EDIT, NULL, NULL);
    SendMessageW(g_hSniEdit, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);

    g_hRegSniLabel = CreateLabel(
        hwnd, TrW(STR_REG_SNI_LABEL), 0, 0, 10, 18);
    g_hRegSniEdit = CreateWindowExW(
        0, L"EDIT", L"" DEFAULT_REG_SNI,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL,
        0, 0, 10, UI_ROW_H, hwnd, (HMENU)(INT_PTR)IDC_REGSNI_EDIT, NULL, NULL);
    SendMessageW(g_hRegSniEdit, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);

    g_hRestoreBtn = CreateWindowExW(
        0, L"BUTTON", TrW(STR_RESTORE_BTN),
        WS_CHILD | WS_TABSTOP,
        0, 0, 10, UI_BTN_H, hwnd, (HMENU)(INT_PTR)IDC_RESTORE_BTN, NULL, NULL);
    SendMessageW(g_hRestoreBtn, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);
    g_hPatchBtn = CreateWindowExW(
        0, L"BUTTON", TrW(STR_PATCH_BTN),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        0, 0, 10, UI_BTN_H, hwnd, (HMENU)(INT_PTR)IDC_PATCH_BTN, NULL, NULL);
    SendMessageW(g_hPatchBtn, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);

    g_hLogLabel = CreateWindowExW(
        0, L"STATIC", TrW(STR_LOG_LABEL), WS_CHILD | SS_LEFT,
        0, 0, 10, 18, hwnd, NULL, NULL, NULL);
    SendMessageW(g_hLogLabel, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);

    g_hLog = CreateWindowExW(
        0, L"EDIT", L"",
        WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_LOG_EDIT, NULL, NULL);
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_hMonoFont, TRUE);

    LayoutControls(hwnd);
    UpdateRestoreButton(hwnd);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
        g_hMainWindow = hwnd;
        g_mainThreadId = GetCurrentThreadId();
        CreateControls(hwnd);
        AutoResizeToFitContent(hwnd);
        ApplyAppTheme(hwnd);
        return 0;

    case WM_APP_LOG:
    {
        char* text = (char*)lParam;
        if (text)
        {
            AppendLogText(text);
            free(text);
        }
        return 0;
    }

    case WM_APP_WORKER_DONE:
    {
        BOOL isRestore = (BOOL)wParam;
        BOOL success = (BOOL)lParam;

        if (g_hWorkerThread)
        {
            CloseHandle(g_hWorkerThread);
            g_hWorkerThread = NULL;
        }

        SetUiBusy(FALSE, isRestore);

        if (!isRestore)
        {
            g_isPatched = success;
            if (g_hPatchBtn)
            {
                SetWindowTextW(g_hPatchBtn, success ? TrW(STR_STATUS_PATCHED) : TrW(STR_PATCH_BTN));
            }
        }
        else
        {
            g_isPatched = FALSE;
            if (g_hRestoreBtn)
            {
                SetWindowTextW(g_hRestoreBtn, TrW(STR_RESTORE_BTN));
            }
            if (g_hPatchBtn)
            {
                SetWindowTextW(g_hPatchBtn, TrW(STR_PATCH_BTN));
            }
        }
        UpdateRestoreButton(hwnd);
        return 0;
    }

    case WM_ACTIVATE:
        if (LOWORD(wParam) != WA_INACTIVE && g_hWorkerThread == NULL)
        {
            UpdateRestoreButton(hwnd);
        }
        return 0;

    case WM_ERASEBKGND:
        if (g_darkMode && g_hWndBrush)
        {
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect((HDC)wParam, &rc, g_hWndBrush);
            return 1;
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_PATCH_BTN:
            OnPatchClicked(hwnd);
            return 0;
        case IDC_RESTORE_BTN:
            OnRestoreClicked(hwnd);
            return 0;
        case IDC_LANG_BTN:
            if (g_hWorkerThread == NULL && g_hLangBtn)
            {
                RECT rc;
                GetWindowRect(g_hLangBtn, &rc);
                HMENU hMenu = CreatePopupMenu();
                if (hMenu)
                {
                    AppendMenuW(hMenu, MF_STRING | (!I18nIsRussian() ? MF_CHECKED : 0),
                                IDM_LANG_EN, L"EN");
                    AppendMenuW(hMenu, MF_STRING | (I18nIsRussian() ? MF_CHECKED : 0),
                                IDM_LANG_RU, L"РУ");

                    int cmd = TrackPopupMenuEx(hMenu,
                        TPM_RIGHTALIGN | TPM_TOPALIGN | TPM_LEFTBUTTON | TPM_RIGHTBUTTON | TPM_RETURNCMD,
                        rc.right, rc.bottom, hwnd, NULL);
                    DestroyMenu(hMenu);

                    if (cmd == IDM_LANG_EN && I18nIsRussian())
                    {
                        I18nSetRussian(FALSE);
                        UpdateUiLanguage(hwnd);
                    }
                    else if (cmd == IDM_LANG_RU && !I18nIsRussian())
                    {
                        I18nSetRussian(TRUE);
                        UpdateUiLanguage(hwnd);
                    }
                }
            }
            return 0;
        case IDC_SNI_EDIT:
        case IDC_REGSNI_EDIT:
            if (HIWORD(wParam) == EN_CHANGE && g_hPatchBtn && g_hWorkerThread == NULL)
            {
                g_isPatched = FALSE;
                SetWindowTextW(g_hPatchBtn, TrW(STR_PATCH_BTN));
            }
            return 0;
        }
        break;

    case WM_CLOSE:
        if (g_hWorkerThread != NULL)
        {
            MessageBoxW(hwnd,
                TrW(STR_MSG_OP_IN_PROGRESS),
                TrW(STR_APP_TITLE), MB_ICONWARNING | MB_OK);
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_SIZE:
        LayoutControls(hwnd);
        return 0;

    /* Paint control text/backgrounds to match the current theme. In light mode
       we fall through to the default handling so the classic look is kept. */
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORBTN:
        if (g_darkMode)
        {
            HDC hdc = (HDC)wParam;
            /* Edit fields and the read-only log (which reports as STATIC) get
               the lighter field background; labels get the window background. */
            BOOL isField = (msg == WM_CTLCOLOREDIT) || ((HWND)lParam == g_hLog);
            if ((HWND)lParam == g_hHintLabel)
            {
                SetTextColor(hdc, RGB(0x9E, 0x9E, 0x9E));
            }
            else
            {
                SetTextColor(hdc, DARK_TEXT);
            }
            SetBkColor(hdc, isField ? DARK_CTLBG : DARK_BG);
            return (LRESULT)(isField ? g_hCtlBrush : g_hWndBrush);
        }
        else if ((HWND)lParam == g_hHintLabel)
        {
            HDC hdc = (HDC)wParam;
            SetTextColor(hdc, RGB(0x55, 0x55, 0x55));
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }
        break;

    /* The system light/dark setting changed: re-apply live. */
    case WM_SETTINGCHANGE:
        if (lParam && (_wcsicmp((const wchar_t*)lParam, L"ImmersiveColorSet") == 0 ||
                       _stricmp((const char*)lParam, "ImmersiveColorSet") == 0))
        {
            ApplyAppTheme(hwnd);
        }
        return 0;

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        int cw = UI_MIN_WIDTH;
        if (hwnd)
        {
            RECT rcClient;
            if (GetClientRect(hwnd, &rcClient) && (rcClient.right - rcClient.left) > UI_MIN_WIDTH)
            {
                cw = rcClient.right - rcClient.left;
            }
        }
        int fieldW = cw - UI_MARGIN * 2;
        int hintW = fieldW - UI_LANG_BTN_W - 8;
        if (hintW < 80) hintW = 80;
        int compactH = GetCompactContentHeight(hwnd, hintW);
        int minClientH = g_logVisible ? (compactH + 22 + 80) : compactH;

        RECT rc = { 0, 0, UI_MIN_WIDTH, minClientH };
        AdjustWindowRect(&rc, (DWORD)GetWindowLongPtrW(hwnd, GWL_STYLE), FALSE);
        mmi->ptMinTrackSize.x = rc.right - rc.left;
        mmi->ptMinTrackSize.y = rc.bottom - rc.top;
        return 0;
    }

    case WM_EXITSIZEMOVE:
        if (!g_logVisible)
        {
            AutoResizeToFitContent(hwnd);
        }
        return 0;

    case WM_DESTROY:
        if (g_hWorkerThread)
        {
            WaitForSingleObject(g_hWorkerThread, 5000);
            CloseHandle(g_hWorkerThread);
            g_hWorkerThread = NULL;
        }
        if (g_hUiFont)
        {
            DeleteObject(g_hUiFont);
            g_hUiFont = NULL;
        }
        if (g_hMonoFont)
        {
            DeleteObject(g_hMonoFont);
            g_hMonoFont = NULL;
        }
        if (g_hWndBrush)
        {
            DeleteObject(g_hWndBrush);
            g_hWndBrush = NULL;
        }
        if (g_hCtlBrush)
        {
            DeleteObject(g_hCtlBrush);
            g_hCtlBrush = NULL;
        }
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int RunGui(HINSTANCE hInstance, int nCmdShow, int argc, char** argv)
{
    WNDCLASSEXW wc;
    HWND hwnd;
    MSG msg{};
    const wchar_t* className = L"WarpSniPatcherWindow";
    int i;


    I18nInit(NULL);
    for (i = 1; i < argc; ++i)
    {
        if (_stricmp(argv[i], "--ru") == 0) I18nSetRussian(TRUE);
        else if (_stricmp(argv[i], "--en") == 0) I18nSetRussian(FALSE);
        else if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) g_target = argv[++i];
    }

    g_mainThreadId = GetCurrentThreadId();

    {
        /* Opt into comctl32 v6 so buttons, scrollbars and the frame render
           with the modern (themed) visual style rather than classic chrome. */
        INITCOMMONCONTROLSEX icc;
        icc.dwSize = sizeof(icc);
        icc.dwICC = ICC_STANDARD_CLASSES;
        InitCommonControlsEx(&icc);
    }

    /* Opt the process into dark mode before any window exists, then each window
       picks up the current light/dark system setting in WM_CREATE. */
    InitDarkModeSupport();

    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = className;
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_APPICON));
    wc.hIconSm = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_APPICON));

    if (!RegisterClassExW(&wc))
    {
        MessageBoxW(NULL, TrW(STR_ERR_REGISTER_CLASS), TrW(STR_APP_TITLE), MB_ICONERROR);
        return 1;
    }

    {
        /* Fixed-size window (non-resizable); layout auto-fits content programmatically. */
        DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        RECT rc = { 0, 0, 500, UI_COMPACT_CLIENT_H };
        int winW, winH, x, y;
        RECT work;

        AdjustWindowRect(&rc, style, FALSE);
        winW = rc.right - rc.left;
        winH = rc.bottom - rc.top;

        /* Center on the primary monitor's work area. CW_USEDEFAULT is avoided
           deliberately: for a process's first top-level window it derives the
           position from the launch STARTUPINFO, and elevated launches often
           pass (0,0) -- which parks the window in the top-left corner. */
        if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0))
        {
            x = work.left + ((work.right - work.left) - winW) / 2;
            y = work.top + ((work.bottom - work.top) - winH) / 2;
        }
        else
        {
            x = CW_USEDEFAULT;
            y = CW_USEDEFAULT;
        }

        hwnd = CreateWindowExW(
            0, className, TrW(STR_APP_TITLE), style,
            x, y, winW, winH,
            NULL, NULL, hInstance, NULL);
    }
    if (!hwnd)
    {
        MessageBoxW(NULL, TrW(STR_ERR_CREATE_WINDOW), TrW(STR_APP_TITLE), MB_ICONERROR);
        return 1;
    }

    {
        RECT rcWin, work;
        if (GetWindowRect(hwnd, &rcWin) && SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0))
        {
            int w = rcWin.right - rcWin.left;
            int h = rcWin.bottom - rcWin.top;
            int cx = work.left + ((work.right - work.left) - w) / 2;
            int cy = work.top + ((work.bottom - work.top) - h) / 2;
            SetWindowPos(hwnd, NULL, cx, cy, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }

    for (i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--sni") == 0) SetWindowTextA(g_hSniEdit, argv[++i]);
        else if (strcmp(argv[i], "--reg-api") == 0) SetWindowTextA(g_hRegSniEdit, argv[++i]);
    }
    warp::SetLogCallback(GuiLog, nullptr);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        if (!IsDialogMessageW(hwnd, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    warp::SetLogCallback(nullptr, nullptr);
    return (int)msg.wParam;
}




namespace warp {
int RunGui(int argc, char** argv) {
    return ::RunGui(GetModuleHandle(NULL), SW_SHOWDEFAULT, argc, argv);
}
}




#endif // _WIN32
