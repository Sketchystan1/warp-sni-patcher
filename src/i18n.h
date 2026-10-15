#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <wchar.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#elif defined(__APPLE__) || defined(__OBJC__)
#include <objc/objc.h>
#ifndef TRUE
#define TRUE YES
#endif
#ifndef FALSE
#define FALSE NO
#endif
#else
#include <strings.h>
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
typedef int BOOL;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /* UI Strings */
    STR_APP_TITLE,
    STR_TIP_HINT,
    STR_MASQUE_SNI_LABEL,
    STR_REG_SNI_LABEL,
    STR_RESTORE_BTN,
    STR_PATCH_BTN,
    STR_LOG_LABEL,
    STR_STATUS_PATCHING,
    STR_STATUS_RESTORING,
    STR_STATUS_PATCHED,
    STR_MSG_OP_IN_PROGRESS,
    STR_ERR_REGISTER_CLASS,
    STR_ERR_CREATE_WINDOW,

    /* Logging / Status Strings */
    STR_LOG_STOP_SERVICE,
    STR_LOG_START_SERVICE,
    STR_LOG_CLEANING_USERENV,
    STR_LOG_CLEANED_USERENV,
    STR_LOG_DISCONNECTING,
    STR_LOG_RECONNECT_NOTE,
    STR_LOG_BACKUP,
    STR_LOG_PATCHING,
    STR_LOG_DONE,
    STR_LOG_RESTORED_OK,

    /* Warnings / Errors */
    STR_LOG_ERR_STOP_SERVICE_ADMIN,
    STR_LOG_ERR_STOP_SERVICE,
    STR_LOG_ERR_STOP_TIMEOUT,
    STR_LOG_ERR_START_SERVICE,
    STR_LOG_ERR_OPEN_SERVICE_START,
    STR_LOG_ERR_START_TIMEOUT,
    STR_LOG_ERR_SCM_ADMIN,
    STR_LOG_ERR_ACCESS_SERVICE,
    STR_LOG_ERR_CHECK_SERVICE_STATUS,
    STR_LOG_ERR_DELETE_USERENV,
    STR_LOG_ERR_PATCH_FAILED,
    STR_LOG_ERR_RESTORE_FAILED,
    STR_LOG_ERR_NO_BACKUP,
    STR_LOG_ERR_BACKUP_DIFF_VER,
    STR_LOG_ERR_CURRENT_UNPATCHED,
    STR_LOG_ERR_DELETE_BACKUP_FRESH,
    STR_LOG_ERR_BACKUP_NO_ORIG_HOSTS,
    STR_LOG_ERR_BACKUP_UNSUPPORTED,
    STR_LOG_ERR_TARGET_NOT_FOUND,
    STR_LOG_ERR_CHECK_INSTALL,
    STR_LOG_ERR_MEM_ALLOC,
    STR_LOG_ERR_THREAD_CREATE,
    STR_LOG_ERR_OPEN_FILE,
    STR_LOG_ERR_INVALID_SIZE,
    STR_LOG_ERR_NOT_ENOUGH_MEM,
    STR_LOG_ERR_READ_FILE,
    STR_LOG_ERR_SAVE_CHANGES_ADMIN,
    STR_LOG_ERR_WRITE_FILE,
    STR_LOG_ERR_FILE_TOO_SMALL,
    STR_LOG_ERR_NOT_VALID_PE,
    STR_LOG_ERR_PE_HEADER_INVALID,
    STR_LOG_ERR_X64_ONLY,
    STR_LOG_ERR_EMPTY_SNI,
    STR_LOG_ERR_SNI_TOO_LONG,
    STR_LOG_TIP_DEFAULT_SNI,
    STR_LOG_ERR_EMPTY_REG_SNI,
    STR_LOG_ERR_REG_SNI_TOO_LONG,
    STR_LOG_TIP_DEFAULT_REG_SNI,
    STR_LOG_ERR_FIND_WARP_SVC,
    STR_LOG_ERR_VERIFY_PATH,
    STR_LOG_ERR_NO_ORIG_HOSTS_AND_NO_BACKUP,
    STR_LOG_ERR_ALREADY_PATCHED_OR_UNSUPPORTED,
    STR_LOG_ERR_REG_HOSTNAME_TOO_LONG,
    STR_LOG_ERR_REG_UPDATE_UNSAFE,

    STR_COUNT
} StringId;

typedef struct {
    const char* en;
    const char* ru;
    const wchar_t* enW;
    const wchar_t* ruW;
} I18N_ENTRY;

#define ENTRY(id, enStr, ruStr) { enStr, ruStr, L##enStr, L##ruStr }

inline const I18N_ENTRY g_table[STR_COUNT] = {
    /* UI Strings */
    ENTRY(STR_APP_TITLE,
        "WARP SNI Patcher",
        "WARP SNI Patcher"),

    ENTRY(STR_TIP_HINT,
        "Replaces blocked WARP hostnames to restore connection.\nPre-filled hosts are recommended. Just click Patch.",
        "Заменяет заблокированные имена хостов WARP для восстановления подключения.\nРекомендуется использовать уже заполненные значения. Просто нажмите «Пропатчить»."),

    ENTRY(STR_MASQUE_SNI_LABEL,
        "New MASQUE SNI hostname",
        "Новое имя хоста MASQUE SNI"),

    ENTRY(STR_REG_SNI_LABEL,
        "New registration API hostname",
        "Новое имя хоста API регистрации"),

    ENTRY(STR_RESTORE_BTN,
        "Restore",
        "Восстановить"),

    ENTRY(STR_PATCH_BTN,
        "Patch",
        "Пропатчить"),

    ENTRY(STR_LOG_LABEL,
        "Log",
        "Журнал"),

    ENTRY(STR_STATUS_PATCHING,
        "Patching...",
        "Применение..."),

    ENTRY(STR_STATUS_RESTORING,
        "Restoring...",
        "Восстановление..."),

    ENTRY(STR_STATUS_PATCHED,
        "Patched",
        "Пропатчено"),

    ENTRY(STR_MSG_OP_IN_PROGRESS,
        "An operation is currently in progress. Please wait until it completes before closing.",
        "Выполняется операция. Пожалуйста, дождитесь ее завершения перед закрытием."),

    ENTRY(STR_ERR_REGISTER_CLASS,
        "Failed to register window class.",
        "Не удалось зарегистрировать класс окна."),

    ENTRY(STR_ERR_CREATE_WINDOW,
        "Failed to create window.",
        "Не удалось создать окно."),

    /* Logging / Status Strings */
    ENTRY(STR_LOG_STOP_SERVICE,
        "Stop service...",
        "Остановка службы..."),

    ENTRY(STR_LOG_START_SERVICE,
        "Start service...",
        "Запуск службы..."),

    ENTRY(STR_LOG_CLEANING_USERENV,
        "Cleaning up leftover userenv.dll.",
        "Очистка остаточного файла userenv.dll..."),

    ENTRY(STR_LOG_CLEANED_USERENV,
        "Cleaned up leftover userenv.dll.",
        "Остаточный файл userenv.dll удален."),

    ENTRY(STR_LOG_DISCONNECTING,
        "Disconnecting...",
        "Отключение туннеля..."),

    ENTRY(STR_LOG_RECONNECT_NOTE,
        "Note: You can reconnect the tunnel using the Cloudflare WARP app.",
        "Примечание: вы можете повторно подключить туннель через приложение Cloudflare WARP."),

    ENTRY(STR_LOG_BACKUP,
        "Backup...",
        "Создание резервной копии..."),

    ENTRY(STR_LOG_PATCHING,
        "Patching...",
        "Применение патча..."),

    ENTRY(STR_LOG_DONE,
        "Done!",
        "Готово!"),

    ENTRY(STR_LOG_RESTORED_OK,
        "Original file restored from backup.",
        "Исходный файл восстановлен из резервной копии."),

    /* Warnings / Errors */
    ENTRY(STR_LOG_ERR_STOP_SERVICE_ADMIN,
        "[!] Could not stop Cloudflare WARP service. Please ensure the app is running as Administrator.",
        "[!] Не удалось остановить службу Cloudflare WARP. Убедитесь, что приложение запущено от имени администратора."),

    ENTRY(STR_LOG_ERR_STOP_SERVICE,
        "[!] Could not stop Cloudflare WARP service.",
        "[!] Не удалось остановить службу Cloudflare WARP."),

    ENTRY(STR_LOG_ERR_STOP_TIMEOUT,
        "[!] Cloudflare WARP service took too long to stop.",
        "[!] Остановка службы Cloudflare WARP заняла слишком много времени."),

    ENTRY(STR_LOG_ERR_START_SERVICE,
        "[!] Could not start Cloudflare WARP service.",
        "[!] Не удалось запустить службу Cloudflare WARP."),

    ENTRY(STR_LOG_ERR_OPEN_SERVICE_START,
        "[!] Could not open Cloudflare WARP service to start it.",
        "[!] Не удалось открыть службу Cloudflare WARP для запуска."),

    ENTRY(STR_LOG_ERR_START_TIMEOUT,
        "[!] Cloudflare WARP service took too long to start.",
        "[!] Запуск службы Cloudflare WARP занял слишком много времени."),

    ENTRY(STR_LOG_ERR_SCM_ADMIN,
        "[!] Could not connect to Windows Service Manager. Please run as Administrator.",
        "[!] Не удалось подключиться к диспетчеру служб Windows. Запустите программу от имени администратора."),

    ENTRY(STR_LOG_ERR_ACCESS_SERVICE,
        "[!] Could not access Cloudflare WARP service.",
        "[!] Не удалось получить доступ к службе Cloudflare WARP."),

    ENTRY(STR_LOG_ERR_CHECK_SERVICE_STATUS,
        "[!] Could not check service status.",
        "[!] Не удалось проверить статус службы."),

    ENTRY(STR_LOG_ERR_DELETE_USERENV,
        "[!] Could not remove leftover '%s'.",
        "[!] Не удалось удалить остаточный файл '%s'."),

    ENTRY(STR_LOG_ERR_PATCH_FAILED,
        "[!] Patch could not be applied. Your original files were left unchanged.",
        "[!] Не удалось применить патч. Исходные файлы остались без изменений."),

    ENTRY(STR_LOG_ERR_RESTORE_FAILED,
        "[!] Restore could not be completed. Please check that a .bak backup file exists.",
        "[!] Не удалось выполнить восстановление. Проверьте наличие файла резервной копии .bak."),

    ENTRY(STR_LOG_ERR_NO_BACKUP,
        "[!] No backup file found. There is nothing to restore.",
        "[!] Файл резервной копии не найден. Нечего восстанавливать."),

    ENTRY(STR_LOG_ERR_BACKUP_DIFF_VER,
        "[!] The backup file is from a different version of Cloudflare WARP.",
        "[!] Файл резервной копии относится к другой версии Cloudflare WARP."),

    ENTRY(STR_LOG_ERR_CURRENT_UNPATCHED,
        "    The current warp-svc.exe is already an original unpatched version.",
        "    Текущий warp-svc.exe уже является оригинальной непропатченной версией."),

    ENTRY(STR_LOG_ERR_DELETE_BACKUP_FRESH,
        "    Please delete '%s' and re-run against a fresh installation.",
        "    Пожалуйста, удалите '%s' и запустите повторно на чистой установке."),

    ENTRY(STR_LOG_ERR_BACKUP_NO_ORIG_HOSTS,
        "[!] Could not find original hostnames in the backup file.",
        "[!] Не удалось найти исходные имена хостов в файле резервной копии."),

    ENTRY(STR_LOG_ERR_BACKUP_UNSUPPORTED,
        "    This version of Cloudflare WARP may not be supported.",
        "    Возможно, эта версия Cloudflare WARP не поддерживается."),

    ENTRY(STR_LOG_ERR_TARGET_NOT_FOUND,
        "[!] Cloudflare WARP service executable not found at:",
        "[!] Исполняемый файл службы Cloudflare WARP не найден по адресу:"),

    ENTRY(STR_LOG_ERR_CHECK_INSTALL,
        "    Please make sure Cloudflare WARP is installed.",
        "    Убедитесь, что Cloudflare WARP установлен."),

    ENTRY(STR_LOG_ERR_MEM_ALLOC,
        "[!] Memory allocation failed.",
        "[!] Ошибка выделения памяти."),

    ENTRY(STR_LOG_ERR_THREAD_CREATE,
        "[!] Failed to create background thread.",
        "[!] Не удалось создать фоновый поток."),

    ENTRY(STR_LOG_ERR_OPEN_FILE,
        "[!] Unable to open '%s'. Please check that the file exists and is accessible.",
        "[!] Не удалось открыть '%s'. Проверьте, существует ли файл и доступен ли он."),

    ENTRY(STR_LOG_ERR_INVALID_SIZE,
        "[!] The file '%s' has an invalid size.",
        "[!] Файл '%s' имеет недопустимый размер."),

    ENTRY(STR_LOG_ERR_NOT_ENOUGH_MEM,
        "[!] Not enough memory to read '%s'.",
        "[!] Недостаточно памяти для чтения '%s'."),

    ENTRY(STR_LOG_ERR_READ_FILE,
        "[!] Could not read '%s'.",
        "[!] Не удалось прочитать '%s'."),

    ENTRY(STR_LOG_ERR_SAVE_CHANGES_ADMIN,
        "[!] Unable to save changes to '%s'. Please ensure the app is running as Administrator.",
        "[!] Не удалось сохранить изменения в '%s'. Убедитесь, что приложение запущено от имени администратора."),

    ENTRY(STR_LOG_ERR_WRITE_FILE,
        "[!] Could not write to '%s'. Please check available disk space and permissions.",
        "[!] Не удалось записать в '%s'. Проверьте свободное место на диске и права доступа."),

    ENTRY(STR_LOG_ERR_FILE_TOO_SMALL,
        "[!] The selected file is too small to be a valid executable.",
        "[!] Выбранный файл слишком мал, чтобы быть исполняемым."),

    ENTRY(STR_LOG_ERR_NOT_VALID_PE,
        "[!] The selected file is not a valid Windows executable.",
        "[!] Выбранный файл не является корректным исполняемым файлом Windows."),

    ENTRY(STR_LOG_ERR_PE_HEADER_INVALID,
        "[!] The executable file header is invalid.",
        "[!] Заголовок исполняемого файла поврежден."),

    ENTRY(STR_LOG_ERR_X64_ONLY,
        "[!] Only 64-bit (x64) versions of Cloudflare WARP are supported.",
        "[!] Поддерживаются только 64-битные (x64) версии Cloudflare WARP."),

    ENTRY(STR_LOG_ERR_EMPTY_SNI,
        "[!] MASQUE SNI cannot be empty. Please enter a hostname (e.g. %s).",
        "[!] MASQUE SNI не может быть пустым. Введите имя хоста (например, %s)."),

    ENTRY(STR_LOG_ERR_SNI_TOO_LONG,
        "[!] The MASQUE SNI '%s' is too long (%zu characters; maximum allowed is %zu).",
        "[!] Имя хоста MASQUE SNI '%s' слишком длинное (%zu симв.; максимум %zu)."),

    ENTRY(STR_LOG_TIP_DEFAULT_SNI,
        "    Tip: The default '%s' is recommended.",
        "    Совет: рекомендуется использовать значение по умолчанию '%s'."),

    ENTRY(STR_LOG_ERR_EMPTY_REG_SNI,
        "[!] Registration API hostname cannot be empty. Please enter a hostname (e.g. %s).",
        "[!] Имя хоста API регистрации не может быть пустым. Введите имя хоста (например, %s)."),

    ENTRY(STR_LOG_ERR_REG_SNI_TOO_LONG,
        "[!] The registration hostname is too long (maximum %zu characters).",
        "[!] Имя хоста регистрации слишком длинное (максимум %zu симв.)."),

    ENTRY(STR_LOG_TIP_DEFAULT_REG_SNI,
        "    Tip: The default '%s' is recommended.",
        "    Совет: рекомендуется использовать значение по умолчанию '%s'."),

    ENTRY(STR_LOG_ERR_FIND_WARP_SVC,
        "[!] Could not find warp-svc.exe at: %s",
        "[!] Не удалось найти warp-svc.exe по адресу: %s"),

    ENTRY(STR_LOG_ERR_VERIFY_PATH,
        "    Please verify the installation path.",
        "    Пожалуйста, проверьте путь установки."),

    ENTRY(STR_LOG_ERR_NO_ORIG_HOSTS_AND_NO_BACKUP,
        "[!] Could not find original hostnames in warp-svc.exe and no backup exists.",
        "[!] В warp-svc.exe не найдены исходные имена хостов, и резервная копия отсутствует."),

    ENTRY(STR_LOG_ERR_ALREADY_PATCHED_OR_UNSUPPORTED,
        "    The file may already be patched, or this version of WARP is not supported.",
        "    Возможно, файл уже пропатчен или эта версия WARP не поддерживается."),

    ENTRY(STR_LOG_ERR_REG_HOSTNAME_TOO_LONG,
        "[!] Registration hostname '%s' is too long (%zu characters; maximum is %zu).",
        "[!] Имя хоста регистрации '%s' слишком длинное (%zu симв.; максимум %zu)."),

    ENTRY(STR_LOG_ERR_REG_UPDATE_UNSAFE,
        "[!] Could not safely update registration hostname in this version of WARP.",
        "[!] Не удалось безопасно обновить имя хоста регистрации в этой версии WARP.")
};

#undef ENTRY

inline BOOL g_i18n_initialized = FALSE;
inline BOOL g_i18n_isRussian = FALSE;

inline BOOL DetectRussianLanguage(const char* cmdLine)
{
    /* 1. Explicit command line overrides */
    if (cmdLine)
    {
        if (strstr(cmdLine, "--ru") || strstr(cmdLine, "-ru") ||
            strstr(cmdLine, "/ru") || strstr(cmdLine, "lang=ru") ||
            strstr(cmdLine, "lang:ru"))
        {
            return TRUE;
        }
        if (strstr(cmdLine, "--en") || strstr(cmdLine, "-en") ||
            strstr(cmdLine, "/en") || strstr(cmdLine, "lang=en") ||
            strstr(cmdLine, "lang:en"))
        {
            return FALSE;
        }
    }

    /* 2. Environment variable overrides */
#ifdef _WIN32
    {
        char envLang[32];
        DWORD len = GetEnvironmentVariableA("WARP_PATCHER_LANG", envLang, sizeof(envLang));
        if (len > 0 && len < sizeof(envLang))
        {
            envLang[len] = '\0';
            if (_strnicmp(envLang, "ru", 2) == 0) return TRUE;
            if (_strnicmp(envLang, "en", 2) == 0) return FALSE;
        }

        len = GetEnvironmentVariableA("LANG", envLang, sizeof(envLang));
        if (len > 0 && len < sizeof(envLang))
        {
            envLang[len] = '\0';
            if (_strnicmp(envLang, "ru", 2) == 0) return TRUE;
            if (_strnicmp(envLang, "en", 2) == 0) return FALSE;
        }
    }

    /* 3. Windows preferred UI languages list */
    {
        ULONG numLangs = 0, cch = 0;
        if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &numLangs, NULL, &cch) && cch > 0)
        {
            wchar_t* buf = (wchar_t*)malloc(cch * sizeof(wchar_t));
            if (buf)
            {
                if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &numLangs, buf, &cch))
                {
                    if (_wcsnicmp(buf, L"ru", 2) == 0)
                    {
                        free(buf);
                        return TRUE;
                    }
                }
                free(buf);
            }
        }
    }

    /* 4. Windows UI languages and user/system locales */
    if (PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_RUSSIAN) return TRUE;
    if (PRIMARYLANGID(GetSystemDefaultUILanguage()) == LANG_RUSSIAN) return TRUE;
    if (PRIMARYLANGID(GetUserDefaultLangID()) == LANG_RUSSIAN) return TRUE;
    if (PRIMARYLANGID(GetSystemDefaultLangID()) == LANG_RUSSIAN) return TRUE;
#else
    {
        const char* names[] = { "WARP_PATCHER_LANG", "LC_ALL", "LC_MESSAGES", "LANG" };
        size_t i;
        for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
        {
            const char* language = getenv(names[i]);
            if (!language || !*language) continue;
            if (strncasecmp(language, "ru", 2) == 0) return TRUE;
            return FALSE;
        }
    }
#endif

    return FALSE;
}

inline void I18nInit(const char* cmdLine)
{
    g_i18n_isRussian = DetectRussianLanguage(cmdLine);
    g_i18n_initialized = TRUE;
}

inline BOOL I18nIsRussian(void)
{
    if (!g_i18n_initialized)
    {
        I18nInit(NULL);
    }
    return g_i18n_isRussian;
}

inline void I18nSetRussian(BOOL isRussian)
{
    g_i18n_isRussian = isRussian;
    g_i18n_initialized = TRUE;
}

inline void I18nToggleLanguage(void)
{
    if (!g_i18n_initialized)
    {
        I18nInit(NULL);
    }
    g_i18n_isRussian = !g_i18n_isRussian;
}

inline const char* Tr(StringId id)
{
    if (!g_i18n_initialized)
    {
        I18nInit(NULL);
    }
    if ((unsigned int)id >= STR_COUNT)
    {
        return "";
    }
    return g_i18n_isRussian ? g_table[id].ru : g_table[id].en;
}

inline const wchar_t* TrW(StringId id)
{
    if (!g_i18n_initialized)
    {
        I18nInit(NULL);
    }
    if ((unsigned int)id >= STR_COUNT)
    {
        return L"";
    }
    return g_i18n_isRussian ? g_table[id].ruW : g_table[id].enW;
}

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <string>

inline std::string TranslateLogMessage(const std::string& msg) {
    if (!I18nIsRussian()) {
        return msg;
    }

    std::string s = msg;
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) {
        s.pop_back();
    }

    if (s == "Stopping Cloudflare WARP service..." || s == "Stop service..." || s == "Stopping Cloudflare WARP daemon...") {
        return Tr(STR_LOG_STOP_SERVICE);
    }
    if (s == "Starting Cloudflare WARP service..." || s == "Start service..." || s == "Starting Cloudflare WARP daemon...") {
        return Tr(STR_LOG_START_SERVICE);
    }
    if (s == "Disconnecting Cloudflare WARP tunnel..." || s == "Disconnecting...") {
        return Tr(STR_LOG_DISCONNECTING);
    }
    if (s == "Reconnecting Cloudflare WARP tunnel..." || s == "Reconnecting...") {
        return "Повторное подключение туннеля...";
    }
    if (s == "Backup...") {
        return Tr(STR_LOG_BACKUP);
    }
    if (s == "Patching...") {
        return Tr(STR_LOG_PATCHING);
    }
    if (s == "Done!") {
        return Tr(STR_LOG_DONE);
    }
    if (s == "Original file restored from backup.") {
        return Tr(STR_LOG_RESTORED_OK);
    }
    if (s.rfind("[!] Could not write to: ", 0) == 0) {
        return "[!] Не удалось записать в: " + s.substr(24);
    }
    if (s.rfind("[!] Backup file not found: ", 0) == 0) {
        return "[!] Файл резервной копии не найден: " + s.substr(27);
    }
    if (s.rfind("[!] Could not open target: ", 0) == 0) {
        return "[!] Не удалось открыть целевой файл: " + s.substr(27);
    }
    if (s.rfind("[!] Could not stop WARP service.", 0) == 0) {
        return Tr(STR_LOG_ERR_STOP_SERVICE_ADMIN);
    }
    if (s.rfind("[!] Restore failed: ", 0) == 0) {
        return "[!] Ошибка восстановления: " + s.substr(20);
    }
    if (s.rfind("Note: You can reconnect", 0) == 0) {
        return Tr(STR_LOG_RECONNECT_NOTE);
    }

    return msg;
}
#endif
