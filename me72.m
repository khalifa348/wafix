// ME72 minimal test dylib — marker + test hooks ONLY.
// NO dyld interpose, NO resolver swizzle, NO NSURL/NSFileManager/NSDictionary swizzles,
// NO country-DB synthesis, NO hiding. ME71b proved machinery-free loads clean.
// Goal: drive the 3 emulation-proven leads with crafted values on-device.
//
// ME72j: FAST constructor. Crash forensics (WhatsApp .ips 07:11/07:13) showed
// the 6x3s=18s retry loop exceeding the 20s process-launch watchdog allowance
// -> SIGKILL "app doesn't stay". Hooks all attach on attempt 1 (marker-proven),
// so retries shrink to 4x250ms (~1s total).
//
// Strategy: hook the vulnerable entry points via ObjC method swizzling ONLY
// (no dyld interpose), feed out-of-range values, log what happens to marker file.
// If a crafted value crashes the app -> on-device proof of the lead.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <pthread.h>
#import <objc/message.h>

static NSString *wa_markerPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wafix_marker.txt"];
}

static pthread_mutex_t g_markerLock = PTHREAD_MUTEX_INITIALIZER;

static void wa_marker(NSString *msg) {
    pthread_mutex_lock(&g_markerLock);
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:wa_markerPath()];
    if (!fh) {
        [[NSFileManager defaultManager] createFileAtPath:wa_markerPath() contents:nil attributes:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:wa_markerPath()];
    }
    if (!fh) { pthread_mutex_unlock(&g_markerLock); return; }
    @try {
        [fh seekToEndOfFile];
        [fh writeData:[[msg stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } @catch (NSException *e) {}
    pthread_mutex_unlock(&g_markerLock);
}

// ---------------------------------------------------------------------------
// Test hooks: we ONLY swizzle to OBSERVE (call original), except the "trigger"
// round which deliberately feeds a crafted value. Controlled by marker file
// contents: "TRIGGER:1" enables crafted input for lead 1.
// ---------------------------------------------------------------------------

// REAL selectors from objc_methods dumps (OLD 26.22.76 = our base):
//   Lead 1: XMPPConnectionMain processPersistedStanza:inPersistentStanzaQueue:isFromDeferredNSEMerge:nseMergeCompletion:  0x102a69c88
//   Lead 2: XMPP preprocessRekeyStanza:completion:  0x104810d20
//   Lead 3: WAMessageDecryptionProcessor processMessage:input:cancellationHandle:completion:  0x102fda67c

static void (*orig_processPersistedStanza)(id, SEL, id, id, BOOL, id);
static void hook_processPersistedStanza(id self, SEL _cmd, id stanza, id queue, BOOL deferred, id mergeCompletion) {
    wa_marker([NSString stringWithFormat:@"[hook] processPersistedStanza:inPersistentStanzaQueue:... stanza=%@", stanza ? NSStringFromClass([stanza class]) : @"nil"]);
    orig_processPersistedStanza(self, _cmd, stanza, queue, deferred, mergeCompletion);
}

static void (*orig_preprocessRekey)(id, SEL, id, id);
static void hook_preprocessRekey(id self, SEL _cmd, id stanza, id completion) {
    wa_marker([NSString stringWithFormat:@"[hook] preprocessRekeyStanza:completion: stanza=%@", stanza ? NSStringFromClass([stanza class]) : @"nil"]);
    orig_preprocessRekey(self, _cmd, stanza, completion);
}

static int g_rekeyXMPPHooked = 0; // XMPP.XMPP (emulation-proven lead) hooked
static int g_rekeyAnyHooked = 0;  // some other class carrying the selector hooked
static int g_persistHooked = 0;   // XMPPConnectionMain processPersistedStanza hooked
static int g_msgHooked = 0;       // WAMessageDecryptionProcessor processMessage hooked

static void (*orig_processMessage)(id, SEL, id, id, id, id, id);
static void hook_processMessage(id self, SEL _cmd, id msg, id ctx, id src, id deps, id completion) {
    wa_marker([NSString stringWithFormat:@"[hook] processMessage:... msg=%@", msg ? NSStringFromClass([msg class]) : @"nil"]);
    orig_processMessage(self, _cmd, msg, ctx, src, deps, completion);
}

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

// ---------------------------------------------------------------------------
// SELF-DRIVE (t3b): after hooks attach, call the 3 orig IMPs directly with
// crafted payloads (emulation shapes) and log the outcome. A crash here
// produces an .ips whose PC we correlate with the RE'd target addresses.
//   Lead 1: OLD has cmp #9 guard -> expect GUARD-CAUGHT (control).
//   Lead 2: OLD UNGUARDED second-call result -> weak path (signal).
//   Lead 3: OLD cmp #3 jump table -> expect guarded (control).
// ---------------------------------------------------------------------------

// ME72m: crafted instances are calloc + manual isa. class_createInstance is
// CF_RETURNS_RETAINED -> clang emits a balancing objc_release EVEN for
// __unsafe_unretained (ME72l crash 09:36:58 run_drive_inline+488 = the release
// call at 0x5148, BEFORE the orig call at 0x51ac) -> dealloc of the
// uninitialized object -> dispatch_channel_cancel(NULL) SIGSEGV 0x8.
// calloc+isa has NO +1, ARC never sees it, no release, no dealloc.
// Instances are deliberately leaked (process is killed anyway).
static id craftedInstanceOfClass(Class c) {
    if (!c) return nil;
    size_t sz = class_getInstanceSize(c);
    void *mem = calloc(1, sz ? sz : 16);
    if (!mem) return nil;
    *(void **)mem = (__bridge void *)c;   // set isa
    return (__bridge id)mem;
}

// Empty completion blocks (global constants — no captures, no copy/release).
static void (^const g_emptyComp)(void) = ^{};

// ME72m: temporary override so OLD lead2 passes its first gate
// ([self fromDeviceJID] -> cbz bail) and reaches the unchecked
// isBotChat-result consumption (NEW added cmp x0,#2; b.lo after the same
// sequence; OLD passes 0/1 through unguarded).
static id drive_fromDeviceJID(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return (id)@"drive@override.invalid";
}

static void run_drive_inline(void) {
    // Runs inside waInit on the main thread BEFORE the app can be suspended.
    // Background-app suspension froze the pthread usleep in ME72j (process
    // alive, marker stuck after "thread entered"). Inline = no suspension.
    //
    // ME72l: crafted instances/blocks are __unsafe_unretained — ARC's
    // objc_storeStrong(&self,nil) at scope end triggered dealloc of the
    // UNINITIALIZED class_createInstance object -> dispatch_channel_cancel(NULL)
    // SIGSEGV 0x8 (crash 09:22:47, run_drive_inline+380) BEFORE lead2 ran.
    // ME72m: calloc+isa instances (no +1, no release) + fromDeviceJID override.
    wa_marker(@"[drive] inline drive starting");

    // Lead 2 — OLD unchecked path (the interesting one on 26.22.76).
    // Run FIRST: if it crashes (expected), we capture it before anything else.
    if (orig_preprocessRekey) {
        wa_marker(@"[drive] lead2: calling orig preprocessRekeyStanza:completion:...");
        Class c = NSClassFromString(@"WACallManagerBase");
        __unsafe_unretained id self2 = craftedInstanceOfClass(c);
        // Force fromDeviceJID non-nil so OLD passes its first gate; restore after.
        Method jidM = c ? class_getInstanceMethod(c, NSSelectorFromString(@"fromDeviceJID")) : NULL;
        IMP savedJID = jidM ? method_getImplementation(jidM) : NULL;
        if (jidM) method_setImplementation(jidM, (IMP)drive_fromDeviceJID);
        orig_preprocessRekey(self2, NSSelectorFromString(@"preprocessRekeyStanza:completion:"), nil, g_emptyComp);
        if (jidM && savedJID) method_setImplementation(jidM, savedJID);
        wa_marker(@"[drive] lead2: RETURNED");
    } else {
        wa_marker(@"[drive] lead2: SKIP (orig not hooked)");
    }

    // Lead 1 — crafted nseMergeCompletion whose first int32 is huge.
    if (orig_processPersistedStanza) {
        wa_marker(@"[drive] lead1: calling orig with crafted mergeCompletion...");
        Class c = NSClassFromString(@"XMPPConnectionMain");
        __unsafe_unretained id self1 = craftedInstanceOfClass(c);
        orig_processPersistedStanza(self1,
            NSSelectorFromString(@"processPersistedStanza:inPersistentStanzaQueue:isFromDeferredNSEMerge:nseMergeCompletion:"),
            nil, nil, NO, g_emptyComp);
        wa_marker(@"[drive] lead1: RETURNED (guard caught / safe path)");
    } else {
        wa_marker(@"[drive] lead1: SKIP (orig not hooked)");
    }

    // Lead 3 — OLD cmp #3 jump table (control).
    if (orig_processMessage) {
        wa_marker(@"[drive] lead3: calling orig processMessage:...");
        Class c = NSClassFromString(@"WAMessageDecryptionProcessor");
        __unsafe_unretained id self3 = craftedInstanceOfClass(c);
        orig_processMessage(self3,
            NSSelectorFromString(@"processMessage:input:cancellationHandle:completion:"),
            nil, nil, nil, g_emptyComp);
        wa_marker(@"[drive] lead3: RETURNED");
    } else {
        wa_marker(@"[drive] lead3: SKIP (orig not hooked)");
    }

    wa_marker(@"[drive] inline drive complete");
}

__attribute__((constructor))
static void waInit(void) {
    @autoreleasepool {
        wa_marker(@"=== waContainerFix ME72 (minimal, no machinery) constructor ===");

        // ME72j: process-launch watchdog allows only 20s TOTAL (crash logs
        // 07:11/07:13 proved 18s of usleep -> SIGKILL). Hooks attach on
        // attempt 1 anyway; keep 4x250ms retries for late-registering classes.
        for (int attempt = 0; attempt < 4; attempt++) {
            Class c1 = NSClassFromString(@"XMPPConnectionMain");
            Class c3 = NSClassFromString(@"WAMessageDecryptionProcessor");
            if (!g_persistHooked && c1) {
                wa_swizzle(c1, NSSelectorFromString(@"processPersistedStanza:inPersistentStanzaQueue:isFromDeferredNSEMerge:nseMergeCompletion:"), (IMP)hook_processPersistedStanza, (void **)&orig_processPersistedStanza);
                g_persistHooked = 1;
            }
            if (!g_msgHooked && c3) {
                wa_swizzle(c3, NSSelectorFromString(@"processMessage:input:cancellationHandle:completion:"), (IMP)hook_processMessage, (void **)&orig_processMessage);
                g_msgHooked = 1;
            }
            // Prefer the emulation-proven XMPP.XMPP (Swift) implementation.
            if (!g_rekeyXMPPHooked) {
                Class swiftCls = NSClassFromString(@"XMPP.XMPP");
                SEL rkSel = NSSelectorFromString(@"preprocessRekeyStanza:completion:");
                Method m2 = swiftCls ? class_getInstanceMethod(swiftCls, rkSel) : NULL;
                wa_marker([NSString stringWithFormat:@"[scan] XMPP.XMPP cls=%d mthd=%d", swiftCls ? 1 : 0, m2 ? 1 : 0]);
                if (m2) {
                    wa_swizzle(swiftCls, rkSel, (IMP)hook_preprocessRekey, (void **)&orig_preprocessRekey);
                    wa_marker(@"[scan] XMPP.XMPP (Swift) preprocessRekey hooked");
                    g_rekeyXMPPHooked = 1;
                }
            }
            if (!g_rekeyXMPPHooked && !g_rekeyAnyHooked) {
                // Find the DECLARING owner (own method list, not inherited):
                // class_getInstanceMethod also matches subclasses, so break-on-
                // first-hit can hook a subclass instead of the real owner.
                // Prefer XMPP-named owners (emulation-proven class).
                SEL sel = NSSelectorFromString(@"preprocessRekeyStanza:completion:");
                int n = objc_getClassList(NULL, 0);
                Class *buf = (Class *)malloc(sizeof(Class) * n);
                objc_getClassList(buf, n);
                Class found = NULL;
                Class foundXMPP = NULL;
                for (int i = 0; i < n; i++) {
                    Class cls = buf[i];
                    // skip classes whose own list lacks the selector (inherited only)
                    unsigned int mc = 0;
                    Method *ml = class_copyMethodList(cls, &mc);
                    int owns = 0;
                    for (unsigned int j = 0; j < mc; j++) {
                        if (method_getName(ml[j]) == sel) { owns = 1; break; }
                    }
                    free(ml);
                    if (!owns) continue;
                    if (!found) found = cls;
                    const char *nm = class_getName(cls);
                    if (nm && strstr(nm, "XMPP")) { foundXMPP = cls; break; }
                }
                Class target = foundXMPP ? foundXMPP : found;
                if (target) {
                    wa_swizzle(target, sel, (IMP)hook_preprocessRekey, (void **)&orig_preprocessRekey);
                    wa_marker([NSString stringWithFormat:@"[scan] preprocessRekey owner found: %s (x%p)", class_getName(target), target]);
                    g_rekeyAnyHooked = 1;
                } else {
                    wa_marker(@"[scan] preprocessRekey no declaring owner loaded yet");
                }
                free(buf);
            }
            int hooked = (orig_processPersistedStanza ? 1 : 0) + (orig_preprocessRekey ? 1 : 0) + (orig_processMessage ? 1 : 0);
            wa_marker([NSString stringWithFormat:@"[init] attempt %d: %d/3 classes hooked", attempt + 1, hooked]);
            usleep(250000);
        }
        wa_marker(@"[init] ME72 constructor complete");

        // Drive inline on the main thread — a detached pthread gets frozen
        // when iOS suspends the background app (usleep never returns).
        run_drive_inline();
    }
}
