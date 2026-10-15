#include "../src/patcher.h"
#include "../src/service.h"
#include "../src/i18n.h"
#include "../src/formats/formats.h"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond) do { \
    g_tests_run++; \
    if (!(cond)) { \
        std::fprintf(stderr, "[FAIL] %s:%d: Assertion failed: %s\n", __FILE__, __LINE__, #cond); \
        g_tests_failed++; \
    } \
} while(0)

#define TEST_THROWS(expr, exc_type) do { \
    g_tests_run++; \
    bool caught = false; \
    try { \
        expr; \
    } catch (const exc_type&) { \
        caught = true; \
    } catch (...) {} \
    if (!caught) { \
        std::fprintf(stderr, "[FAIL] %s:%d: Expected exception: %s\n", __FILE__, __LINE__, #exc_type); \
        g_tests_failed++; \
    } \
} while(0)

static void TestValidateHostname() {
    std::cout << "[*] Testing ValidateHostname..." << std::endl;

    // Valid hostnames
    warp::ValidateHostname("speed.cloudflare.com");
    warp::ValidateHostname("speed.cloudflare.com.");
    warp::ValidateHostname("api.devices.cloudflare.com");
    warp::ValidateHostname("localhost");
    warp::ValidateHostname("sub-domain.example.org");

    // Invalid hostnames
    TEST_THROWS(warp::ValidateHostname(""), std::runtime_error);
    TEST_THROWS(warp::ValidateHostname("."), std::runtime_error);
    TEST_THROWS(warp::ValidateHostname(".."), std::runtime_error);
    TEST_THROWS(warp::ValidateHostname("-bad.com"), std::runtime_error);
    TEST_THROWS(warp::ValidateHostname("bad-.com"), std::runtime_error);
    TEST_THROWS(warp::ValidateHostname("bad..domain.com"), std::runtime_error);
    TEST_THROWS(warp::ValidateHostname("has space.com"), std::runtime_error);
    TEST_THROWS(warp::ValidateHostname("https://example.com"), std::runtime_error);

    std::string long_label(64, 'a');
    TEST_THROWS(warp::ValidateHostname(long_label + ".com"), std::runtime_error);

    std::string long_domain(254, 'a');
    TEST_THROWS(warp::ValidateHostname(long_domain), std::runtime_error);
}

static void TestFormatDetection() {
    std::cout << "[*] Testing format detection..." << std::endl;

    // PE magic
    warp::Bytes pe_data = {'M', 'Z', 0, 0, 0, 0};
    TEST_ASSERT(warp::is_pe(pe_data));
    TEST_ASSERT(!warp::is_elf(pe_data));
    TEST_ASSERT(!warp::is_macho(pe_data));

    // ELF magic
    warp::Bytes elf_data = {0x7f, 'E', 'L', 'F', 2, 1, 1, 0};
    TEST_ASSERT(warp::is_elf(elf_data));
    TEST_ASSERT(!warp::is_pe(elf_data));
    TEST_ASSERT(!warp::is_macho(elf_data));

    // Mach-O magic (x86_64, arm64, fat)
    warp::Bytes macho_64 = {0xcf, 0xfa, 0xed, 0xfe};
    TEST_ASSERT(warp::is_macho(macho_64));
    TEST_ASSERT(!warp::is_elf(macho_64));

    warp::Bytes macho_fat = {0xca, 0xfe, 0xba, 0xbe};
    TEST_ASSERT(warp::is_macho(macho_fat));
}

static void TestUtilities() {
    std::cout << "[*] Testing utilities..." << std::endl;

    std::string bak = warp::BuildBackupPath("warp-svc.exe");
    TEST_ASSERT(bak == "warp-svc.exe.bak");

    TEST_ASSERT(!warp::FileExists("this_file_should_not_exist_xyz_12345.bin"));
}

static void TestTranslations() {
    std::cout << "[*] Testing translations (i18n)..." << std::endl;

    I18nInit(nullptr);
    I18nSetRussian(FALSE);
    TEST_ASSERT(std::strcmp(Tr(STR_APP_TITLE), "WARP SNI Patcher") == 0);
    TEST_ASSERT(std::strcmp(Tr(STR_RESTORE_BTN), "Restore") == 0);
    TEST_ASSERT(std::strcmp(Tr(STR_PATCH_BTN), "Patch") == 0);

    I18nSetRussian(TRUE);
    TEST_ASSERT(std::strcmp(Tr(STR_RESTORE_BTN), "Восстановить") == 0);
    TEST_ASSERT(std::strcmp(Tr(STR_PATCH_BTN), "Пропатчить") == 0);

    std::string translated = TranslateLogMessage("Stopping Cloudflare WARP service...");
    TEST_ASSERT(translated == Tr(STR_LOG_STOP_SERVICE));

    // Reset back to English
    I18nSetRussian(FALSE);
}

int main(int argc, char** argv) {
    std::cout << "=== Running WARP SNI Patcher Unit Tests ===" << std::endl;

    TestValidateHostname();
    TestFormatDetection();
    TestUtilities();
    TestTranslations();

    std::cout << "-------------------------------------------" << std::endl;
    std::cout << "Tests run: " << g_tests_run << ", Failures: " << g_tests_failed << std::endl;

    if (g_tests_failed > 0) {
        std::cerr << "[!] Some tests failed!" << std::endl;
        return 1;
    }

    std::cout << "[+] All unit tests passed successfully!" << std::endl;
    return 0;
}
