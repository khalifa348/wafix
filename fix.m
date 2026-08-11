// wa_container_fix.m — WhatsAppSMB sideload fix dylib (v2).
//
// ME28 finding: the dylib loads, but the main thread STILL aborts at
// +[NSURL fileURLWithPath:] with a nil path (SharedModules+0x10e560, same
// offset as ME25). The nil does NOT come from containerURLForSecurityApplicationGroupIdentifier:
// (that swizzle alone didn't help). So v2:
//   1. nil-guard +[NSURL fileURLWithPath:]  -> return NSHomeDirectory URL
//   2. nil-guard +[NSURL fileURLWithPath:isDirectory:]
//   3. keep the container swizzle (harmless, may help other paths)
//   4. os_log/NSLog breadcrumbs so syslog proves which swizzles ran and
//      what group IDs / nil paths the app asks for.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <os/log.h>

static os_log_t wa_log(void) {
    static os_log_t l;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ l = os_log_create("com.wafix", "dylib"); });
    return l;
}

// ---- 1. container swizzle (keep) ----
static NSURL *wa_fake_container(id self, SEL _cmd, NSString *groupIdentifier) {
    (void)self; (void)_cmd;
    os_log_info(wa_log(), "containerURL(%@) -> NSHomeDirectory", groupIdentifier);
    return [NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES];
}

// ---- 2. fileURLWithPath: nil-guard ----
static NSURL *(*orig_fileURLWithPath)(id, SEL, id);
static NSURL *wa_fileURLWithPath(id self, SEL _cmd, id path) {
    if (!path) {
        os_log_fault(wa_log(), "fileURLWithPath:nil GUARDED -> home");
        return [NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES];
    }
    return orig_fileURLWithPath(self, _cmd, path);
}

static NSURL *(*orig_fileURLWithPath_isDir)(id, SEL, id, BOOL);
static NSURL *wa_fileURLWithPath_isDir(id self, SEL _cmd, id path, BOOL isDir) {
    if (!path) {
        os_log_fault(wa_log(), "fileURLWithPath:isDirectory: nil GUARDED -> home");
        return [NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES];
    }
    return orig_fileURLWithPath_isDir(self, _cmd, path, isDir);
}

__attribute__((constructor))
static void wa_install_swizzle(void) {
    os_log_info(wa_log(), "waContainerFix v2 constructor running");

    // container swizzle
    Method m = class_getInstanceMethod([NSFileManager class],
        @selector(containerURLForSecurityApplicationGroupIdentifier:));
    if (m) {
        class_replaceMethod([NSFileManager class],
            @selector(containerURLForSecurityApplicationGroupIdentifier:),
            (IMP)wa_fake_container, method_getTypeEncoding(m));
        os_log_info(wa_log(), "swizzled containerURLForSecurityApplicationGroupIdentifier");
    } else {
        os_log_fault(wa_log(), "containerURL method NOT FOUND");
    }

    // fileURLWithPath: guard
    Method m2 = class_getClassMethod([NSURL class], @selector(fileURLWithPath:));
    if (m2) {
        orig_fileURLWithPath = (void *)method_getImplementation(m2);
        method_setImplementation(m2, (IMP)wa_fileURLWithPath);
        os_log_info(wa_log(), "swizzled +[NSURL fileURLWithPath:]");
    } else {
        os_log_fault(wa_log(), "fileURLWithPath: NOT FOUND");
    }

    // fileURLWithPath:isDirectory: guard
    Method m3 = class_getClassMethod([NSURL class], @selector(fileURLWithPath:isDirectory:));
    if (m3) {
        orig_fileURLWithPath_isDir = (void *)method_getImplementation(m3);
        method_setImplementation(m3, (IMP)wa_fileURLWithPath_isDir);
        os_log_info(wa_log(), "swizzled +[NSURL fileURLWithPath:isDirectory:]");
    } else {
        os_log_fault(wa_log(), "fileURLWithPath:isDirectory: NOT FOUND");
    }
}
