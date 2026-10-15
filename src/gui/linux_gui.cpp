/*
 * WARP SNI Patcher - Linux FLTK GUI Implementation
 */

#include "gui.h"
#include "../patcher.h"
#include "../service.h"
#include "../i18n.h"

#if !defined(_WIN32) && !defined(__APPLE__)
#if !defined(WARP_NO_GUI)
/* ============================================================================
 * Linux FLTK Desktop GUI
 * ============================================================================ */


#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/Fl_Scrollbar.H>
#include <FL/Fl_PNG_Image.H>
#include <FL/fl_draw.H>
#include <FL/fl_ask.H>

#include <algorithm>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <utility>

#if defined(__linux__)
#include <dlfcn.h>
static void InitFontconfig() {
    void* handle = dlopen("libfontconfig.so.1", RTLD_LAZY);
    if (!handle) handle = dlopen("libfontconfig.so", RTLD_LAZY);
    if (handle) {
        typedef int (*FcInitFunc)();
        FcInitFunc init_fn = reinterpret_cast<FcInitFunc>(dlsym(handle, "FcInit"));
        if (init_fn) init_fn();
        dlclose(handle);
    }
}
#endif

static std::string CleanFltkString(const char* s) {
    if (!s) return "";
    std::string str(s);
    str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());
    return str;
}

namespace {

// 32x32 RGBA PNG icon matching app.ico
static const unsigned char EMBEDDED_ICON_PNG[] = {
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x08, 0x06, 0x00, 0x00, 0x00, 0x73, 0x7a, 0x7a,
    0xf4, 0x00, 0x00, 0x00, 0x01, 0x73, 0x52, 0x47, 0x42, 0x00, 0xae, 0xce, 0x1c, 0xe9, 0x00, 0x00,
    0x00, 0x04, 0x67, 0x41, 0x4d, 0x41, 0x00, 0x00, 0xb1, 0x8f, 0x0b, 0xfc, 0x61, 0x05, 0x00, 0x00,
    0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0e, 0xc3, 0x00, 0x00, 0x0e, 0xc3, 0x01, 0xc7,
    0x6f, 0xa8, 0x64, 0x00, 0x00, 0x00, 0xc3, 0x49, 0x44, 0x41, 0x54, 0x58, 0x47, 0xed, 0x94, 0x4d,
    0x0a, 0xc2, 0x30, 0x10, 0x85, 0x7b, 0x08, 0x77, 0x5e, 0xc0, 0x9d, 0x47, 0x71, 0xeb, 0xc5, 0x3c,
    0x8d, 0x5e, 0x4a, 0x70, 0xe7, 0x22, 0x32, 0x81, 0x37, 0xbc, 0x4c, 0xff, 0x62, 0xc8, 0x04, 0x0a,
    0xf3, 0xe0, 0x83, 0xd2, 0xa6, 0x7d, 0x5f, 0x93, 0xb4, 0xd3, 0x14, 0x89, 0x1c, 0x38, 0x69, 0x07,
    0xb7, 0xe4, 0x82, 0xf7, 0xfd, 0x9c, 0x3e, 0xaf, 0x4b, 0xfa, 0x3e, 0x4e, 0x05, 0x72, 0xde, 0x53,
    0x22, 0x17, 0x08, 0xb6, 0x18, 0x48, 0x70, 0xdc, 0x5b, 0xa4, 0xaa, 0x98, 0x43, 0x12, 0x4d, 0xb1,
    0x6b, 0x3a, 0x2b, 0x5d, 0xc2, 0xa6, 0x55, 0xa2, 0x28, 0xdc, 0x9b, 0x76, 0xcb, 0x8a, 0x40, 0xb5,
    0x44, 0x1e, 0xcc, 0x0f, 0x68, 0x05, 0xf7, 0xd3, 0xc6, 0xac, 0xca, 0x5f, 0x6f, 0x5b, 0xc3, 0x61,
    0x04, 0x74, 0xad, 0x1c, 0x05, 0x56, 0xf7, 0x83, 0x96, 0xf6, 0x58, 0xfb, 0x25, 0xe4, 0xa7, 0xb5,
    0xb5, 0x27, 0xf2, 0x05, 0xaf, 0x72, 0xc0, 0xcf, 0x67, 0x81, 0xee, 0x53, 0xbe, 0x05, 0xc2, 0xb3,
    0x30, 0x54, 0x00, 0x84, 0xc0, 0x4c, 0x60, 0xa4, 0x04, 0xfa, 0x54, 0xe0, 0x79, 0xbb, 0x0e, 0x93,
    0x40, 0x8f, 0x74, 0x16, 0x5f, 0x02, 0x4b, 0x78, 0x63, 0xcb, 0x55, 0x82, 0x97, 0xc3, 0x0b, 0xf4,
    0xd8, 0x72, 0x0e, 0x0f, 0xf2, 0x22, 0x12, 0x89, 0x68, 0x7e, 0x46, 0x1e, 0xda, 0xcf, 0x5e, 0x21,
    0x15, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82
};

struct Input : public Fl_Input {
    std::function<void()> on_enter;
    std::function<void()> on_change;

    Input(int x, int y, int w, int h, const char* label = nullptr)
        : Fl_Input(x, y, w, h, label) {
        box(FL_FLAT_BOX);
        color(fl_rgb_color(0x2B, 0x2B, 0x2B));
        textcolor(fl_rgb_color(0xE0, 0xE0, 0xE0));
        cursor_color(fl_rgb_color(0xE0, 0xE0, 0xE0));
        textsize(13);
        visible_focus(1);
        when(FL_WHEN_CHANGED);
        callback([](Fl_Widget* w, void*) {
            auto* self = static_cast<Input*>(w);
            if (self->on_change) self->on_change();
        });
    }

    void draw() override {
        Fl_Input::draw();
        // Windows dark mode border: subtle dark when unfocused, accent blue when focused
        if (Fl::focus() == this) {
            fl_color(fl_rgb_color(0x00, 0x78, 0xD4));
        } else {
            fl_color(fl_rgb_color(0x44, 0x44, 0x44));
        }
        fl_rect(x(), y(), w(), h());
    }

    int handle(int event) override {
        if (event == FL_FOCUS || event == FL_UNFOCUS) {
            redraw();
            return 1;
        }
        if (event == FL_KEYDOWN) {
            if (Fl::event_state(FL_CTRL) && (Fl::event_key() == 'a' || Fl::event_key() == 'A')) {
                position(0, size());
                return 1;
            }
            if ((Fl::event_key() == FL_Enter || Fl::event_key() == FL_KP_Enter) && on_enter) {
                on_enter();
                return 1;
            }
        }
        return Fl_Input::handle(event);
    }
};

static void draw_rounded_rectf(int x, int y, int w, int h, int r) {
    if (r <= 0) {
        fl_rectf(x, y, w, h);
        return;
    }
    const int d = 2 * r;
    fl_pie(x, y, d, d, 90, 180);
    fl_pie(x + w - d, y, d, d, 0, 90);
    fl_pie(x + w - d, y + h - d, d, d, 270, 360);
    fl_pie(x, y + h - d, d, d, 180, 270);
    fl_rectf(x + r, y, w - d, h);
    fl_rectf(x, y + r, r, h - d);
    fl_rectf(x + w - r, y + r, r, h - d);
}

static void draw_rounded_rect(int x, int y, int w, int h, int r) {
    if (r <= 0) {
        fl_rect(x, y, w, h);
        return;
    }
    const int d = 2 * r;
    fl_arc(x, y, d, d, 90, 180);
    fl_arc(x + w - d - 1, y, d, d, 0, 90);
    fl_arc(x + w - d - 1, y + h - d - 1, d, d, 270, 360);
    fl_arc(x, y + h - d - 1, d, d, 180, 270);
    fl_line(x + r, y, x + w - r - 1, y);
    fl_line(x + w - 1, y + r, x + w - 1, y + h - r - 1);
    fl_line(x + r, y + h - 1, x + w - r - 1, y + h - 1);
    fl_line(x, y + r, x, y + h - r - 1);
}

struct Button : public Fl_Button {
    bool is_primary = false;

    Button(int x, int y, int w, int h, const char* label = nullptr, bool primary = false)
        : Fl_Button(x, y, w, h, label), is_primary(primary) {
        box(FL_NO_BOX);
        labelsize(13);
        visible_focus(1);
    }

    void draw() override {
        const bool hovered = (Fl::belowmouse() == this);
        const bool pressed = value() != 0;
        const bool enabled = active() != 0;

        Fl_Color bg_color;
        Fl_Color fg_color;
        Fl_Color border_color;

        if (is_primary) {
            if (!enabled) {
                bg_color = fl_rgb_color(0x00, 0x48, 0x80);
                fg_color = fl_rgb_color(0x88, 0x88, 0x88);
                border_color = bg_color;
            } else if (pressed) {
                bg_color = fl_rgb_color(0x00, 0x5A, 0x9E);
                fg_color = FL_WHITE;
                border_color = bg_color;
            } else if (hovered) {
                bg_color = fl_rgb_color(0x10, 0x84, 0xD9);
                fg_color = FL_WHITE;
                border_color = bg_color;
            } else {
                bg_color = fl_rgb_color(0x00, 0x78, 0xD4);
                fg_color = FL_WHITE;
                border_color = bg_color;
            }
        } else {
            if (!enabled) {
                bg_color = fl_rgb_color(0x28, 0x28, 0x28);
                fg_color = fl_rgb_color(0x70, 0x70, 0x70);
                border_color = fl_rgb_color(0x38, 0x38, 0x38);
            } else if (pressed) {
                bg_color = fl_rgb_color(0x28, 0x28, 0x28);
                fg_color = fl_rgb_color(0xE0, 0xE0, 0xE0);
                border_color = fl_rgb_color(0x4C, 0x4C, 0x4C);
            } else if (hovered) {
                bg_color = fl_rgb_color(0x44, 0x44, 0x44);
                fg_color = fl_rgb_color(0xFF, 0xFF, 0xFF);
                border_color = fl_rgb_color(0x55, 0x55, 0x55);
            } else {
                bg_color = fl_rgb_color(0x38, 0x38, 0x38);
                fg_color = fl_rgb_color(0xE0, 0xE0, 0xE0);
                border_color = fl_rgb_color(0x4C, 0x4C, 0x4C);
            }
        }

        // Draw modern 4px rounded rectangle background matching Windows controls
        fl_color(bg_color);
        draw_rounded_rectf(x(), y(), w(), h(), 4);

        // Draw border
        fl_color(border_color);
        draw_rounded_rect(x(), y(), w(), h(), 4);

        // Draw focus outline when focused via keyboard
        if (Fl::focus() == this && visible_focus()) {
            fl_color(is_primary ? FL_WHITE : fl_rgb_color(0xE0, 0xE0, 0xE0));
            fl_line_style(FL_DOT);
            draw_rounded_rect(x() + 2, y() + 2, w() - 4, h() - 4, 2);
            fl_line_style(0);
        }

        labelcolor(fg_color);
        draw_label();
    }

    int handle(int event) override {
        if (event == FL_ENTER || event == FL_LEAVE) {
            redraw();
            return 1;
        }
        if (event == FL_FOCUS || event == FL_UNFOCUS) {
            redraw();
            return 1;
        }
        if (event == FL_KEYDOWN) {
            if (Fl::event_key() == ' ' || Fl::event_key() == FL_Enter || Fl::event_key() == FL_KP_Enter) {
                do_callback();
                return 1;
            }
        }
        if (event == FL_KEYUP) {
            if (Fl::event_key() == ' ' || Fl::event_key() == FL_Enter || Fl::event_key() == FL_KP_Enter) {
                return 1;
            }
        }
        return Fl_Button::handle(event);
    }
};

struct LogDisplay : public Fl_Text_Display {
    LogDisplay(int x, int y, int w, int h)
        : Fl_Text_Display(x, y, w, h) {
        wrap_mode(WRAP_AT_BOUNDS, 0);
        color(fl_rgb_color(0x2B, 0x2B, 0x2B));
        textcolor(fl_rgb_color(0xE0, 0xE0, 0xE0));
        textfont(FL_COURIER);
        textsize(12);
        box(FL_FLAT_BOX);
        scrollbar_width(12);
        scrollbar_align(FL_ALIGN_RIGHT);
        if (mVScrollBar) {
            mVScrollBar->color(fl_rgb_color(0x2B, 0x2B, 0x2B));
            mVScrollBar->selection_color(fl_rgb_color(0x55, 0x55, 0x55));
            mVScrollBar->box(FL_FLAT_BOX);
            mVScrollBar->slider(FL_FLAT_BOX);
        }
        if (mHScrollBar) {
            mHScrollBar->hide();
        }
    }

    void draw() override {
        Fl_Text_Display::draw();
        fl_color(fl_rgb_color(0x44, 0x44, 0x44));
        fl_rect(x(), y(), w(), h());
    }
};

struct MainWindow : public Fl_Double_Window {
    Fl_Box* hint_box = nullptr;
    Button* lang_btn = nullptr;
    Fl_Box* sni_label = nullptr;
    Input* sni_input = nullptr;
    Fl_Box* reg_label = nullptr;
    Input* reg_input = nullptr;
    Button* restore_btn = nullptr;
    Button* patch_btn = nullptr;
    Fl_Box* log_label = nullptr;
    LogDisplay* log_display = nullptr;
    Fl_Text_Buffer* log_buffer = nullptr;
    std::unique_ptr<Fl_PNG_Image> window_icon;

    bool busy = false;
    bool restoring = false;
    bool patched = false;
    bool log_visible = false;
    std::string target_path = DEFAULT_TARGET_PATH;

    static constexpr int WIN_W = 500;
    static constexpr int COMPACT_H = 252;
    static constexpr int EXPANDED_H = 420;

    MainWindow(int w, int h, const char* title)
        : Fl_Double_Window(w, h, title) {
        xclass("warp-sni-patcher");
        color(fl_rgb_color(0x20, 0x20, 0x20));

        // Hint label with secondary muted color #9E9E9E matching Windows
        hint_box = new Fl_Box(16, 16, 404, 40, "");
        hint_box->box(FL_NO_BOX);
        hint_box->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
        hint_box->labelcolor(fl_rgb_color(0x9E, 0x9E, 0x9E));
        hint_box->labelsize(12);

        // Language toggle button in top right (56x24, matching Windows UI_LANG_BTN)
        lang_btn = new Button(WIN_W - 16 - 56, 16, 56, 24, "EN ▾");
        lang_btn->callback([](Fl_Widget*, void* data) {
            auto* self = static_cast<MainWindow*>(data);
            I18nToggleLanguage();
            self->refresh();
        }, this);

        // MASQUE SNI Label and Input
        sni_label = new Fl_Box(16, 66, WIN_W - 32, 20, "");
        sni_label->box(FL_NO_BOX);
        sni_label->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        sni_label->labelcolor(fl_rgb_color(0xE0, 0xE0, 0xE0));
        sni_label->labelsize(12);

        sni_input = new Input(16, 88, WIN_W - 32, 26);
        sni_input->value(DEFAULT_SNI);
        sni_input->on_enter = [this] { start(false); };
        sni_input->on_change = [this] {
            if (patched && !busy) {
                patched = false;
                patch_btn->copy_label(Tr(STR_PATCH_BTN));
            }
        };

        // Registration API Hostname Label and Input
        reg_label = new Fl_Box(16, 120, WIN_W - 32, 20, "");
        reg_label->box(FL_NO_BOX);
        reg_label->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        reg_label->labelcolor(fl_rgb_color(0xE0, 0xE0, 0xE0));
        reg_label->labelsize(12);

        reg_input = new Input(16, 142, WIN_W - 32, 26);
        reg_input->value(DEFAULT_REG_SNI);
        reg_input->on_enter = [this] { start(false); };
        reg_input->on_change = [this] {
            if (patched && !busy) {
                patched = false;
                patch_btn->copy_label(Tr(STR_PATCH_BTN));
            }
        };

        // Action Buttons: Restore (secondary) & Patch (primary)
        // Height is 30px (matching Windows UI_BTN_H = 30)
        restore_btn = new Button(WIN_W - 16 - 130 - 8 - 130, 184, 130, 30, "", false);
        restore_btn->callback([](Fl_Widget*, void* data) {
            static_cast<MainWindow*>(data)->start(true);
        }, this);

        patch_btn = new Button(WIN_W - 16 - 130, 184, 130, 30, "", true);
        patch_btn->callback([](Fl_Widget*, void* data) {
            static_cast<MainWindow*>(data)->start(false);
        }, this);

        // Monospace Operation Log
        log_label = new Fl_Box(16, 226, WIN_W - 32, 20, "");
        log_label->box(FL_NO_BOX);
        log_label->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        log_label->labelcolor(fl_rgb_color(0xE0, 0xE0, 0xE0));
        log_label->labelsize(12);
        log_label->hide();

        log_buffer = new Fl_Text_Buffer();
        log_display = new LogDisplay(16, 248, WIN_W - 32, 156);
        log_display->buffer(log_buffer);
        log_display->hide();

        end();

        size_range(460, COMPACT_H, 1200, COMPACT_H);

        // Set application icon from embedded PNG
        window_icon = std::make_unique<Fl_PNG_Image>("icon.png", EMBEDDED_ICON_PNG, sizeof(EMBEDDED_ICON_PNG));
        if (window_icon->w() > 0 && window_icon->h() > 0) {
            Fl_Window::default_icon(window_icon.get());
            icon(window_icon.get());
        }

        // Window close handler: prevent closing while busy
        callback([](Fl_Widget* w, void*) {
            auto* self = static_cast<MainWindow*>(w);
            if (self->busy) {
                fl_alert("%s", Tr(STR_MSG_OP_IN_PROGRESS));
                return;
            }
            self->hide();
        });
    }

    ~MainWindow() override {
        if (log_display) {
            log_display->buffer(nullptr);
        }
        delete log_buffer;
        log_buffer = nullptr;
    }

    int handle(int event) override {
        if (event == FL_SHORTCUT && Fl::event_key() == FL_Escape) {
            if (busy) {
                fl_alert("%s", Tr(STR_MSG_OP_IN_PROGRESS));
                return 1;
            }
        }
        return Fl_Double_Window::handle(event);
    }

    void refresh() {
        copy_label(CleanFltkString(Tr(STR_APP_TITLE)).c_str());
        hint_box->copy_label(CleanFltkString(Tr(STR_TIP_HINT)).c_str());
        sni_label->copy_label(CleanFltkString(Tr(STR_MASQUE_SNI_LABEL)).c_str());
        reg_label->copy_label(CleanFltkString(Tr(STR_REG_SNI_LABEL)).c_str());
        log_label->copy_label(CleanFltkString(Tr(STR_LOG_LABEL)).c_str());
        lang_btn->copy_label(I18nIsRussian() ? "РУ ▾" : "EN ▾");

        restore_btn->copy_label(CleanFltkString(Tr(busy && restoring ? STR_STATUS_RESTORING : STR_RESTORE_BTN)).c_str());
        patch_btn->copy_label(CleanFltkString(Tr(busy && !restoring ? STR_STATUS_PATCHING :
                                 patched ? STR_STATUS_PATCHED : STR_PATCH_BTN)).c_str());

        std::string backup = warp::BuildBackupPath(target_path);
        const bool show_restore = (busy && restoring) || warp::FileExists(backup);
        if (show_restore) restore_btn->show(); else restore_btn->hide();

        if (busy) {
            lang_btn->deactivate();
            sni_input->deactivate();
            reg_input->deactivate();
            restore_btn->deactivate();
            patch_btn->deactivate();
        } else {
            lang_btn->activate();
            sni_input->activate();
            reg_input->activate();
            restore_btn->activate();
            patch_btn->activate();
        }
        redraw();
    }

    void ensure_log_visible() {
        if (!log_visible) {
            log_visible = true;
            log_label->show();
            log_display->show();
            size_range(460, 380, 1200, 1000);
            size(WIN_W, EXPANDED_H);
        }
    }

    void append_log(const std::string& line) {
        ensure_log_visible();
        std::string s = line;
        s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
        log_buffer->append(s.c_str());
        if (s.empty() || s.back() != '\n') {
            log_buffer->append("\n");
        }
        log_display->scroll(log_buffer->length(), 0);
    }

    void start(bool is_restore) {
        if (busy) return;
        ensure_log_visible();
        log_buffer->text("");

        std::string sni = sni_input->value() ? sni_input->value() : "";
        std::string reg = reg_input->value() ? reg_input->value() : "";

        while (!sni.empty() && (sni.front() == ' ' || sni.front() == '\t')) sni.erase(0, 1);
        while (!sni.empty() && (sni.back() == ' ' || sni.back() == '\t')) sni.pop_back();
        while (!reg.empty() && (reg.front() == ' ' || reg.front() == '\t')) reg.erase(0, 1);
        while (!reg.empty() && (reg.back() == ' ' || reg.back() == '\t')) reg.pop_back();

        if (!is_restore && !warp::FileExists(target_path)) {
            append_log(std::string(Tr(STR_LOG_ERR_TARGET_NOT_FOUND)) + "\n    " + target_path + "\n" + Tr(STR_LOG_ERR_CHECK_INSTALL) + "\n");
            return;
        }

        if (is_restore) {
            std::string backup = warp::BuildBackupPath(target_path);
            if (!warp::FileExists(backup)) {
                append_log(std::string(Tr(STR_LOG_ERR_NO_BACKUP)) + "\n");
                refresh();
                return;
            }
        }

        busy = true;
        restoring = is_restore;
        refresh();

        std::thread([this, is_restore, sni, reg] {
            warp::SetLogCallback([](const char* text, void* user_data) {
                if (!text || !user_data) return;
                std::string line(text);
                std::string translated = TranslateLogMessage(line);
                Fl::awake([](void* data) {
                    auto* pair = static_cast<std::pair<MainWindow*, std::string>*>(data);
                    pair->first->append_log(pair->second);
                    delete pair;
                }, new std::pair<MainWindow*, std::string>(static_cast<MainWindow*>(user_data), translated));
            }, this);

            warp::PatchOptions opts;
            opts.target_path = target_path;
            if (!sni.empty()) opts.masque_host = sni;
            if (!reg.empty()) opts.reg_api_host = reg;
            const bool success = warp::RunOperation(opts, is_restore);
            if (!success) {
                warp::Log("%s", Tr(is_restore ? STR_LOG_ERR_RESTORE_FAILED : STR_LOG_ERR_PATCH_FAILED));
            }

            warp::SetLogCallback(nullptr, nullptr);

            Fl::awake([](void* data) {
                auto* tuple = static_cast<std::tuple<MainWindow*, bool, bool>*>(data);
                auto* self = std::get<0>(*tuple);
                bool ok = std::get<1>(*tuple);
                bool restore = std::get<2>(*tuple);
                self->busy = false;
                if (ok) self->patched = !restore;
                else if (restore) self->patched = false;
                self->refresh();
                delete tuple;
            }, new std::tuple<MainWindow*, bool, bool>(this, success, is_restore));
        }).detach();
    }
};
} // namespace

namespace warp {
int RunGui(int argc, char** argv) {
    try {
#if defined(__linux__)
        InitFontconfig();
#endif
        I18nInit(argc > 0 ? argv[0] : "");
        Fl::lock();
        Fl::visible_focus(1);
        Fl::scheme("gtk+");
        Fl_Window::default_xclass("warp-sni-patcher");

        MainWindow window(MainWindow::WIN_W, MainWindow::COMPACT_H, Tr(STR_APP_TITLE));
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if ((arg == "--target" || arg == "-t") && i + 1 < argc) {
                window.target_path = argv[++i];
            } else if (arg == "--sni" && i + 1 < argc) {
                window.sni_input->value(argv[++i]);
            } else if ((arg == "--reg-api" || arg == "--registration-host") && i + 1 < argc) {
                window.reg_input->value(argv[++i]);
            }
        }
        window.refresh();
        window.show();
        window.sni_input->take_focus();

        return Fl::run();
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
} // namespace warp

#else
namespace warp {
int RunGui(int argc, char** argv) {
    Log("GUI is not enabled in this build. Use CLI options (--help).\n");
    return 1;
}
}
#endif



#endif // !defined(_WIN32) && !defined(__APPLE__)
