/*
 * WARP SNI Patcher -- Win32 GUI.
 *
 * This translation unit owns the window, the controls, and WinMain. It drives
 * the on-disk patching through the core functions declared in the shared
 * header, and provides UiLog() so the core can report progress into the log box.
 *
 * The process runs elevated by default (requireAdministrator manifest embedded
 * at link time) because warp-svc.exe lives under Program Files.
 */

#include "patcher.h"
#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <stdio.h>
#include <stdarg.h>

/* Common-Controls v6 gives buttons, scrollbars and edits the modern themed
   look. The manifest dependency is merged into the linker-embedded manifest;
   InitCommonControlsEx() is called at startup. */
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, \
    "\"/manifestdependency:type='win32' " \
    "name='Microsoft.Windows.Common-Controls' version='6.0.0.0' " \
    "processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

/* Control IDs */
#define IDC_PATH_EDIT    1001
#define IDC_SNI_EDIT     1002
#define IDC_BROWSE_BTN   1003
#define IDC_PATCH_BTN    1004
#define IDC_RESTORE_BTN  1005
#define IDC_LOG_EDIT     1006

/* Layout constants (client-relative pixels). */
#define UI_MARGIN        16
#define UI_ROW_H         26
#define UI_BTN_H         30
#define UI_MIN_WIDTH     420
#define UI_MIN_HEIGHT    320

static HWND g_hLog = NULL;      /* multiline log edit control */
static HFONT g_hUiFont = NULL;  /* Segoe UI, for labels/edits/buttons */
static HFONT g_hMonoFont = NULL;/* Consolas, for the log */

/* Child control handles, kept so WM_SIZE can reflow the layout. */
static HWND g_hPathLabel = NULL;
static HWND g_hPathEdit = NULL;
static HWND g_hBrowseBtn = NULL;
static HWND g_hSniLabel = NULL;
static HWND g_hSniEdit = NULL;
static HWND g_hRestoreBtn = NULL;
static HWND g_hPatchBtn = NULL;
static HWND g_hLogLabel = NULL;

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

static AllowDarkModeForWindow_t p_AllowDarkModeForWindow = NULL;
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
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                          &value, sizeof(value));

    /* Text fields use the dark edit theme (DarkMode_CFD) so their border draws
       dark; the log and buttons use DarkMode_Explorer for the dark scrollbar
       and button styling. NULL resets to the default light theme. */
    {
        const wchar_t* cfd = dark ? L"DarkMode_CFD" : NULL;
        const wchar_t* exp = dark ? L"DarkMode_Explorer" : NULL;
        SetWindowTheme(g_hPathEdit, cfd, NULL);
        SetWindowTheme(g_hSniEdit, cfd, NULL);
        SetWindowTheme(g_hLog, exp, NULL);
        SetWindowTheme(g_hBrowseBtn, exp, NULL);
        SetWindowTheme(g_hRestoreBtn, exp, NULL);
        SetWindowTheme(g_hPatchBtn, exp, NULL);
    }

    InvalidateRect(hwnd, NULL, TRUE);
}

/* Create a font by face name and point size (negative height = point size). */
static HFONT MakeFont(const char* face, int pointSize, int weight)
{
    HDC hdc = GetDC(NULL);
    int height = -MulDiv(pointSize, GetDeviceCaps(hdc, LOGPIXELSY), 72);
    HFONT font;
    ReleaseDC(NULL, hdc);

    font = CreateFontA(
        height, 0, 0, 0, weight, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
    return font ? font : (HFONT)GetStockObject(DEFAULT_GUI_FONT);
}

/* Append a formatted line to the GUI log control (CRLF-terminated). */
void UiLog(const char* fmt, ...)
{
    char line[1024];
    va_list args;
    int n;

    va_start(args, fmt);
    n = _vsnprintf(line, sizeof(line) - 3, fmt, args);
    va_end(args);
    if (n < 0)
    {
        n = (int)sizeof(line) - 3;
    }
    line[n] = '\r';
    line[n + 1] = '\n';
    line[n + 2] = '\0';

    if (g_hLog)
    {
        int len = GetWindowTextLengthA(g_hLog);
        SendMessageA(g_hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
        SendMessageA(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)line);
        SendMessageA(g_hLog, EM_SCROLLCARET, 0, 0);
    }
}

static void GetEditText(HWND parent, int id, char* buf, int bufSize)
{
    GetWindowTextA(GetDlgItem(parent, id), buf, bufSize);
}

/* Show the Restore button only when a usable backup exists: the .bak must be
   present AND the same size as the current target. A size mismatch means WARP
   updated the exe after the backup was taken, so the backup is stale and
   restoring it would downgrade the binary -- hide Restore in that case. */
static void UpdateRestoreButton(HWND hwnd)
{
    char target[MAX_PATH];
    char backup[MAX_PATH * 2];
    BOOL show = FALSE;

    if (g_hRestoreBtn)
    {
        GetEditText(hwnd, IDC_PATH_EDIT, target, sizeof(target));
        if (target[0] != '\0' && FileExists(target))
        {
            BuildBackupPath(target, backup, sizeof(backup));
            if (FileExists(backup))
            {
                ULONGLONG bak = FileSize64(backup);
                ULONGLONG cur = FileSize64(target);
                show = (bak != (ULONGLONG)-1 && bak == cur);
            }
        }
        ShowWindow(g_hRestoreBtn, show ? SW_SHOW : SW_HIDE);
    }
}

static void BrowseForTarget(HWND hwnd)
{
    OPENFILENAMEA ofn;
    char path[MAX_PATH];

    GetEditText(hwnd, IDC_PATH_EDIT, path, sizeof(path));

    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "Executable (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = sizeof(path);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrTitle = "Select warp-svc.exe";

    if (GetOpenFileNameA(&ofn))
    {
        SetWindowTextA(GetDlgItem(hwnd, IDC_PATH_EDIT), path);
        UpdateRestoreButton(hwnd);
    }
}

static void OnPatchClicked(HWND hwnd)
{
    char target[MAX_PATH];
    char sni[256];

    GetEditText(hwnd, IDC_PATH_EDIT, target, sizeof(target));
    GetEditText(hwnd, IDC_SNI_EDIT, sni, sizeof(sni));

    if (target[0] == '\0')
    {
        UiLog("[!] WARP service path is empty.");
        return;
    }

    UiLog("=== Patch: SNI -> '%s' ===", sni);

    {
        BOOL wasRunning = FALSE;
        BOOL wasConnected = FALSE;
        BOOL patched;

        /* Bring the tunnel down first (needs the service running) so patching
           does not race a live connection. */
        WarpDisconnectIfConnected(target, &wasConnected);

        if (!StopWarpService(&wasRunning))
        {
            UiLog("[!] Could not stop the service; aborting so the running "
                  "binary is not modified.");
            return;
        }

        /* With the service stopped, clear any sideloaded userenv.dll next to
           the target before we patch and restart. */
        RemoveSideloadedUserenv(target);

        patched = RunPatch(target, sni);

        if (wasRunning)
        {
            StartWarpService();
        }

        /* Restore the tunnel if it was up before we started (needs the service
           running again). */
        if (wasConnected)
        {
            WarpConnect(target);
        }

        UiLog(patched ? "[+] Done." : "[!] Patch failed.");
        UpdateRestoreButton(hwnd);
    }
}

static void OnRestoreClicked(HWND hwnd)
{
    char target[MAX_PATH];

    GetEditText(hwnd, IDC_PATH_EDIT, target, sizeof(target));

    if (target[0] == '\0')
    {
        UiLog("[!] WARP service path is empty.");
        return;
    }

    UiLog("=== Restore original ===");

    {
        BOOL wasRunning = FALSE;
        BOOL restored;

        if (!StopWarpService(&wasRunning))
        {
            UiLog("[!] Could not stop the service; aborting so the running "
                  "binary is not modified.");
            return;
        }

        restored = RunRestore(target);

        if (wasRunning)
        {
            StartWarpService();
        }

        UiLog(restored ? "[+] Done." : "[!] Restore failed.");
        UpdateRestoreButton(hwnd);
    }
}

static HWND CreateLabel(HWND parent, const char* text, int x, int y, int w, int h)
{
    HWND label = CreateWindowExA(
        0, "STATIC", text, WS_CHILD | WS_VISIBLE | SS_LEFT,
        x, y, w, h, parent, NULL, NULL, NULL);
    SendMessageA(label, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);
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
    const int browseW = 88;
    const int btnW = 120;
    const int gap = 8;

    GetClientRect(hwnd, &rc);
    cw = rc.right - rc.left;
    fieldW = cw - m * 2;
    if (fieldW < 120)
    {
        fieldW = 120;
    }
    y = m;

    MoveWindow(g_hPathLabel, m, y, fieldW, 18, TRUE);
    y += 22;
    MoveWindow(g_hPathEdit, m, y, fieldW - browseW - gap, UI_ROW_H, TRUE);
    MoveWindow(g_hBrowseBtn, m + fieldW - browseW, y, browseW, UI_ROW_H, TRUE);
    y += UI_ROW_H + 14;

    MoveWindow(g_hSniLabel, m, y, fieldW, 18, TRUE);
    y += 22;
    MoveWindow(g_hSniEdit, m, y, fieldW, UI_ROW_H, TRUE);
    y += UI_ROW_H + 14;

    MoveWindow(g_hRestoreBtn, m + fieldW - btnW - gap - btnW, y, btnW, UI_BTN_H, TRUE);
    MoveWindow(g_hPatchBtn, m + fieldW - btnW, y, btnW, UI_BTN_H, TRUE);
    y += UI_BTN_H + 16;

    MoveWindow(g_hLogLabel, m, y, fieldW, 18, TRUE);
    y += 22;
    logTop = y;
    MoveWindow(g_hLog, m, logTop, fieldW, rc.bottom - logTop - m, TRUE);
}

static void CreateControls(HWND hwnd)
{
    /* Fonts: Segoe UI for the UI, Consolas for the log. */
    g_hUiFont = MakeFont("Segoe UI", 10, FW_NORMAL);
    g_hMonoFont = MakeFont("Consolas", 10, FW_NORMAL);

    g_hPathLabel = CreateLabel(hwnd, "WARP service executable", 0, 0, 10, 18);
    g_hPathEdit = CreateWindowExA(
        0, "EDIT", DEFAULT_TARGET_PATH,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL,
        0, 0, 10, UI_ROW_H, hwnd, (HMENU)(INT_PTR)IDC_PATH_EDIT, NULL, NULL);
    SendMessageA(g_hPathEdit, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);
    g_hBrowseBtn = CreateWindowExA(
        0, "BUTTON", "Browse...",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        0, 0, 10, UI_ROW_H, hwnd, (HMENU)(INT_PTR)IDC_BROWSE_BTN, NULL, NULL);
    SendMessageA(g_hBrowseBtn, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);

    g_hSniLabel = CreateLabel(hwnd, "New MASQUE SNI hostname", 0, 0, 10, 18);
    g_hSniEdit = CreateWindowExA(
        0, "EDIT", DEFAULT_SNI,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL,
        0, 0, 10, UI_ROW_H, hwnd, (HMENU)(INT_PTR)IDC_SNI_EDIT, NULL, NULL);
    SendMessageA(g_hSniEdit, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);

    g_hRestoreBtn = CreateWindowExA(
        0, "BUTTON", "Restore Original",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        0, 0, 10, UI_BTN_H, hwnd, (HMENU)(INT_PTR)IDC_RESTORE_BTN, NULL, NULL);
    SendMessageA(g_hRestoreBtn, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);
    g_hPatchBtn = CreateWindowExA(
        0, "BUTTON", "Patch",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        0, 0, 10, UI_BTN_H, hwnd, (HMENU)(INT_PTR)IDC_PATCH_BTN, NULL, NULL);
    SendMessageA(g_hPatchBtn, WM_SETFONT, (WPARAM)g_hUiFont, TRUE);

    g_hLogLabel = CreateLabel(hwnd, "Log", 0, 0, 10, 18);
    g_hLog = CreateWindowExA(
        0, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)IDC_LOG_EDIT, NULL, NULL);
    SendMessageA(g_hLog, WM_SETFONT, (WPARAM)g_hMonoFont, TRUE);

    LayoutControls(hwnd);
    UpdateRestoreButton(hwnd);
    UiLog("[*] Ready.");
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
        CreateControls(hwnd);
        ApplyAppTheme(hwnd);
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
        case IDC_BROWSE_BTN:
            BrowseForTarget(hwnd);
            return 0;
        case IDC_PATCH_BTN:
            OnPatchClicked(hwnd);
            return 0;
        case IDC_RESTORE_BTN:
            OnRestoreClicked(hwnd);
            return 0;
        case IDC_PATH_EDIT:
            /* Re-evaluate whether the current path has a matching backup. */
            if (HIWORD(wParam) == EN_CHANGE)
            {
                UpdateRestoreButton(hwnd);
            }
            return 0;
        }
        break;

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
            SetTextColor(hdc, DARK_TEXT);
            SetBkColor(hdc, isField ? DARK_CTLBG : DARK_BG);
            return (LRESULT)(isField ? g_hCtlBrush : g_hWndBrush);
        }
        break;

    /* The system light/dark setting changed: re-apply live. */
    case WM_SETTINGCHANGE:
        if (lParam && lstrcmpiA((const char*)lParam, "ImmersiveColorSet") == 0)
        {
            ApplyAppTheme(hwnd);
        }
        return 0;

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = UI_MIN_WIDTH;
        mmi->ptMinTrackSize.y = UI_MIN_HEIGHT;
        return 0;
    }

    case WM_DESTROY:
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

    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASSEXA wc;
    HWND hwnd;
    MSG msg;
    const char* className = "WarpSniPatcherWindow";

    (void)hPrevInstance;
    (void)lpCmdLine;

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
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = className;
    wc.hIcon = LoadIconA(hInstance, MAKEINTRESOURCEA(IDI_APPICON));
    wc.hIconSm = LoadIconA(hInstance, MAKEINTRESOURCEA(IDI_APPICON));

    if (!RegisterClassExA(&wc))
    {
        MessageBoxA(NULL, "Failed to register window class.", "WARP SNI Patcher", MB_ICONERROR);
        return 1;
    }

    {
        /* Size the window so the client area is exactly 540 x 414. */
        DWORD style = WS_OVERLAPPEDWINDOW;
        RECT rc = { 0, 0, 540, 414 };
        int winW, winH, x, y;
        RECT work;

        AdjustWindowRect(&rc, style, FALSE);
        winW = rc.right - rc.left;
        winH = rc.bottom - rc.top;

        /* Center on the primary monitor's work area. CW_USEDEFAULT is avoided
           deliberately: for a process's first top-level window it derives the
           position from the launch STARTUPINFO, and elevated launches often
           pass (0,0) -- which parks the window in the top-left corner. */
        if (SystemParametersInfoA(SPI_GETWORKAREA, 0, &work, 0))
        {
            x = work.left + ((work.right - work.left) - winW) / 2;
            y = work.top + ((work.bottom - work.top) - winH) / 2;
        }
        else
        {
            x = CW_USEDEFAULT;
            y = CW_USEDEFAULT;
        }

        hwnd = CreateWindowExA(
            0, className, "WARP SNI Patcher", style,
            x, y, winW, winH,
            NULL, NULL, hInstance, NULL);
    }
    if (!hwnd)
    {
        MessageBoxA(NULL, "Failed to create window.", "WARP SNI Patcher", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessageA(&msg, NULL, 0, 0) > 0)
    {
        if (!IsDialogMessageA(hwnd, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int)msg.wParam;
}
