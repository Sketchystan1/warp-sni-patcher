#include "gui.h"
#include "../patcher.h"
#include "../service.h"
#include "../i18n.h"

#import <Cocoa/Cocoa.h>
#include <thread>
#include <unistd.h>

static NSString* Text(StringId id) {
    return [NSString stringWithUTF8String:Tr(id)];
}

@interface WarpWindowController : NSWindowController <NSWindowDelegate, NSApplicationDelegate, NSTextFieldDelegate>
@property(strong) NSTextField* target;
@property(strong) NSTextField* sni;
@property(strong) NSTextField* registration;
@property(strong) NSTextView* log;
@property(strong) NSButton* patch;
@property(strong) NSButton* restore;
@property(strong) NSButton* browse;
@property BOOL busy;
- (instancetype)initWithOptions:(const warp::PatchOptions&)options;
- (void)appendLog:(NSString*)text;
@end

@implementation WarpWindowController
- (instancetype)initWithOptions:(const warp::PatchOptions&)options {
    NSWindow* window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 600, 420)
        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable
        backing:NSBackingStoreBuffered defer:NO];
    self = [super initWithWindow:window];
    if (!self) return nil;
    window.title = Text(STR_APP_TITLE);
    window.releasedWhenClosed = NO;
    window.delegate = self;
    [window center];
    NSView* content = window.contentView;

    NSTextField* hint = [NSTextField wrappingLabelWithString:Text(STR_TIP_HINT)];
    hint.frame = NSMakeRect(20, 347, 560, 55);
    [content addSubview:hint];

    self.target = [self field:@"Service executable" value:options.target_path.c_str() y:309];
    self.target.frame = NSMakeRect(190, 309, 298, 24);
    self.target.delegate = self;
    self.target.target = self;
    self.target.action = @selector(refresh);
    self.browse = [self button:@"Browse…" action:@selector(browseTarget:) x:498 y:308 width:82];
    self.sni = [self field:Text(STR_MASQUE_SNI_LABEL)
        value:options.masque_host.value_or("").c_str() y:272];
    self.registration = [self field:Text(STR_REG_SNI_LABEL)
        value:options.reg_api_host.value_or("").c_str() y:235];
    self.restore = [self button:Text(STR_RESTORE_BTN) action:@selector(restoreClicked:) x:366 y:190 width:100];
    self.patch = [self button:Text(STR_PATCH_BTN) action:@selector(patchClicked:) x:476 y:190 width:104];
    self.patch.keyEquivalent = @"\r";

    NSScrollView* scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 20, 560, 154)];
    scroll.hasVerticalScroller = YES;
    scroll.borderType = NSBezelBorder;
    self.log = [[NSTextView alloc] initWithFrame:scroll.contentView.bounds];
    self.log.editable = NO;
    self.log.richText = NO;
    self.log.font = [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular];
    self.log.autoresizingMask = NSViewWidthSizable;
    self.log.textContainer.widthTracksTextView = YES;
    scroll.documentView = self.log;
    [content addSubview:scroll];
    [self refresh];
    return self;
}

- (NSTextField*)field:(NSString*)label value:(const char*)value y:(CGFloat)y {
    NSTextField* caption = [NSTextField labelWithString:label];
    caption.frame = NSMakeRect(20, y + 2, 165, 20);
    [self.window.contentView addSubview:caption];
    NSTextField* field = [[NSTextField alloc] initWithFrame:NSMakeRect(190, y, 390, 24)];
    field.stringValue = [NSString stringWithUTF8String:value] ?: @"";
    [self.window.contentView addSubview:field];
    return field;
}

- (NSButton*)button:(NSString*)title action:(SEL)action x:(CGFloat)x y:(CGFloat)y width:(CGFloat)width {
    NSButton* button = [NSButton buttonWithTitle:title target:self action:action];
    button.frame = NSMakeRect(x, y, width, 32);
    button.bezelStyle = NSBezelStyleRounded;
    [self.window.contentView addSubview:button];
    return button;
}

- (void)refresh {
    self.target.enabled = self.sni.enabled = self.registration.enabled = !self.busy;
    self.browse.enabled = self.patch.enabled = self.restore.enabled = !self.busy;
    self.restore.hidden = !warp::FileExists(warp::BuildBackupPath(self.target.stringValue.UTF8String));
}

- (void)controlTextDidChange:(NSNotification*)notification {
    (void)notification;
    [self refresh];
}

- (void)browseTarget:(id)sender {
    (void)sender;
    NSOpenPanel* panel = [NSOpenPanel openPanel];
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = NO;
    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse response) {
        if (response == NSModalResponseOK) {
            self.target.stringValue = panel.URL.path;
            [self refresh];
        }
    }];
}

- (void)appendLog:(NSString*)text {
    NSString* line = [text hasSuffix:@"\n"] ? text : [text stringByAppendingString:@"\n"];
    [self.log.textStorage appendAttributedString:[[NSAttributedString alloc] initWithString:line
        attributes:@{NSFontAttributeName: self.log.font, NSForegroundColorAttributeName: NSColor.textColor}]];
    [self.log scrollRangeToVisible:NSMakeRange(self.log.string.length, 0)];
}

- (void)patchClicked:(id)sender { (void)sender; [self start:NO]; }
- (void)restoreClicked:(id)sender { (void)sender; [self start:YES]; }

- (void)start:(BOOL)restore {
    if (self.busy) return;
    self.log.string = @"";
    warp::PatchOptions options;
    options.target_path = self.target.stringValue.UTF8String;
    NSCharacterSet* whitespace = NSCharacterSet.whitespaceAndNewlineCharacterSet;
    NSString* sni = [self.sni.stringValue stringByTrimmingCharactersInSet:whitespace];
    NSString* registration = [self.registration.stringValue stringByTrimmingCharactersInSet:whitespace];
    if (sni.length) options.masque_host = sni.UTF8String;
    if (registration.length) options.reg_api_host = registration.UTF8String;
    if (warp::IsInstalledTarget(options.target_path) && geteuid() != 0) {
        [self appendLog:@"Administrator privileges are required for installed WARP. Quit and launch this executable with sudo and --gui from Terminal, or select a writable copy with Browse."];
        return;
    }

    self.busy = YES;
    self.patch.title = Text(restore ? STR_STATUS_RESTORING : STR_STATUS_PATCHING);
    [self refresh];
    try {
        // Keep the controller alive until the worker and its queued UI updates finish.
        WarpWindowController* controller = self;
        std::thread([controller, options, restore] {
            @autoreleasepool {
                warp::SetLogCallback([](const char* message, void* context) {
                    WarpWindowController* owner = (__bridge WarpWindowController*)context;
                    NSString* line = [NSString stringWithUTF8String:TranslateLogMessage(message).c_str()] ?: @"";
                    dispatch_async(dispatch_get_main_queue(), ^{ [owner appendLog:line]; });
                }, (__bridge void*)controller);
                bool success = false;
                try {
                    success = warp::RunOperation(options, restore);
                } catch (const std::exception& error) {
                    warp::Log("[!] %s", error.what());
                }
                warp::SetLogCallback(nullptr, nullptr);
                dispatch_async(dispatch_get_main_queue(), ^{
                    controller.busy = NO;
                    controller.patch.title = Text(STR_PATCH_BTN);
                    if (!success) [controller appendLog:Text(restore ? STR_LOG_ERR_RESTORE_FAILED : STR_LOG_ERR_PATCH_FAILED)];
                    [controller refresh];
                });
            }
        }).detach();
    } catch (const std::exception& error) {
        self.busy = NO;
        self.patch.title = Text(STR_PATCH_BTN);
        [self appendLog:[NSString stringWithUTF8String:error.what()]];
        [self refresh];
    }
}

- (BOOL)windowShouldClose:(NSWindow*)sender {
    (void)sender;
    if (self.busy) { NSBeep(); return NO; }
    [NSApp stop:nil];
    return YES;
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication*)sender {
    (void)sender;
    if (self.busy) { NSBeep(); return NSTerminateCancel; }
    return NSTerminateNow;
}
@end

namespace warp {
int RunGui(int argc, char** argv) {
    @autoreleasepool {
        I18nInit(argc ? argv[0] : nullptr);
        PatchOptions options;
        options.masque_host = DEFAULT_SNI;
        options.reg_api_host = DEFAULT_REG_SNI;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--ru") I18nSetRussian(TRUE);
            else if (arg == "--en") I18nSetRussian(FALSE);
            else if ((arg == "--target" || arg == "--sni" || arg == "--reg-api") && i + 1 < argc) {
                if (arg == "--target") options.target_path = argv[++i];
                else if (arg == "--sni") options.masque_host = argv[++i];
                else options.reg_api_host = argv[++i];
            }
        }
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        NSMenu* menu = [[NSMenu alloc] init];
        NSMenuItem* app = [[NSMenuItem alloc] init];
        [menu addItem:app];
        NSMenu* appMenu = [[NSMenu alloc] init];
        [appMenu addItemWithTitle:@"Quit WARP SNI Patcher" action:@selector(terminate:) keyEquivalent:@"q"];
        app.submenu = appMenu;
        NSMenuItem* edit = [[NSMenuItem alloc] initWithTitle:@"Edit" action:nil keyEquivalent:@""];
        [menu addItem:edit];
        NSMenu* editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
        [editMenu addItemWithTitle:@"Cut" action:@selector(cut:) keyEquivalent:@"x"];
        [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
        [editMenu addItemWithTitle:@"Paste" action:@selector(paste:) keyEquivalent:@"v"];
        [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
        edit.submenu = editMenu;
        NSApp.mainMenu = menu;
        WarpWindowController* controller = [[WarpWindowController alloc] initWithOptions:options];
        NSApp.delegate = controller;
        [controller showWindow:nil];
        [NSApp activateIgnoringOtherApps:YES];
        [NSApp run];
        NSApp.delegate = nil;
        [controller close];
    }
    return 0;
}
} // namespace warp
