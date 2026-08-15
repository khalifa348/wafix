// ME73b (t8) test dylib — 2 NEW companion-device family sites:
//   fetchPendingRemovalCompanionDevicesForAccountUserJID:        @0x1001A4DD4
//   fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList: @0x101CA1634
// Both read the SAME shared 3-word index struct (thunk 0x1000242A4 -> &0x107d0744c,
// __DATA __objc_ivar, writable; idx0@+0, idx1@+4, UNCHECKED idx2@+0x10) — same t7 bug class.
//
// v3 FIXES (v2 crash was a harness artifact, NOT the target bug):
//   * v2 crafted instance (class_createInstance) dealloc'd with garbage C++ ivars
//     -> objc_storeStrong crash in destructor. The method itself RETURNED — the
//     poked 0x7FFFFFFF loaded garbage from a mapped page (2GB into heap) instead
//     of faulting, then the crafted object's dealloc exploded.
//   * v3 drives with the REAL singleton: the method itself loads x20 from
//     *(0x107ceb520+slide) — the app's own storage-manager instance. We read the
//     same global and message it via objc_msgSend (through our hooks, so orig runs
//     with real self + real table) -> garbage table entry -> real retain in
//     WhatsApp's frame -> crash in WhatsApp, not in our harness.
//   * zeroed-memory fallback instance if the singleton global is not yet set.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>

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

// --- shared global index struct: vmaddr 0x107d0744c; singleton global 0x107ceb520 ---
static const uint64_t kIndexStructVMA = 0x107d0744cULL;
static const uint64_t kSingletonVMA   = 0x107ceb520ULL;
static const uint64_t kImgBase        = 0x100000000ULL;

static void *g_slide_addr(uint64_t vmaddr) {
    uintptr_t slide = _dyld_get_image_vmaddr_slide(0); // main executable
    return (void *)(slide + vmaddr);
}

// --- hooks ---
static void (*orig_fetchPending)(id, SEL, id);
static void hook_fetchPending(id self, SEL _cmd, id jid) {
    wa_marker([NSString stringWithFormat:@"[hook] fetchPendingRemoval... self=%@", NSStringFromClass([self class])]);
    orig_fetchPending(self, _cmd, jid);
}

static void (*orig_fetchLinked)(id, SEL, id, id);
static void hook_fetchLinked(id self, SEL _cmd, id jid, id list) {
    wa_marker([NSString stringWithFormat:@"[hook] fetchLinkedAndPending... self=%@", NSStringFromClass([self class])]);
    orig_fetchLinked(self, _cmd, jid, list);
}

static void wa_swizzle(Class cls, SEL sel, IMP newImp, void **origOut) {
    if (*origOut) return; // already hooked — do NOT clobber
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        wa_marker([NSString stringWithFormat:@"[swz] MISSING %@ %@", NSStringFromClass(cls), NSStringFromSelector(sel)]);
        return;
    }
    *origOut = (void *)method_getImplementation(m);
    IMP old = class_replaceMethod(cls, sel, newImp, method_getTypeEncoding(m));
    wa_marker([NSString stringWithFormat:@"[swz] hooked %@ %@ (orig=%p)", NSStringFromClass(cls), NSStringFromSelector(sel), old]);
}

static Class wa_find_class(SEL sel) {
    unsigned int count = 0;
    Class *list = objc_copyClassList(&count);
    Class hit = nil;
    for (unsigned int i = 0; i < count; i++) {
        Class c = list[i];
        if (class_getInstanceMethod(c, sel)) { hit = c; break; }
    }
    free(list);
    return hit;
}

static int g_hooked = 0;

// real instance: try class singleton accessors first, then the app's own global slot
static id wa_real_instance(Class want) {
    // 1) scan class methods for shared-instance accessors
    if (want) {
        unsigned int mc = 0;
        Method *ml = class_copyMethodList(object_getClass(want), &mc);
        for (unsigned int i = 0; i < mc; i++) {
            SEL s = method_getName(ml[i]);
            const char *n = sel_getName(s);
            if (strstr(n, "shared") || strstr(n, "Shared") || strstr(n, "instance") || strstr(n, "Instance") || strstr(n, "manager") || strstr(n, "Manager")) {
                id obj = ((id(*)(id, SEL))objc_msgSend)((id)want, s);
                if (obj && object_isClass(obj) == NO && [obj isKindOfClass:want]) {
                    wa_marker([NSString stringWithFormat:@"[inst] singleton via +%s", n]);
                    free(ml);
                    return obj;
                }
            }
        }
        free(ml);
        wa_marker(@"[inst] no class-method singleton found — trying app global");
    }
    // 2) app's own global slot (the method itself loads x20 from this address)
    __unsafe_unretained id *slot = (__unsafe_unretained id *)g_slide_addr(kSingletonVMA);
    if (!slot) return nil;
    id obj = *slot;
    if (obj && want && object_isClass(obj) == NO && [obj isKindOfClass:want]) return obj;
    if (obj && object_isClass(obj) == NO) {
        // not the manager class, but v3 proved the method runs to the crash site
        // with this receiver (it is the object the method itself messages)
        wa_marker([NSString stringWithFormat:@"[inst] app global is %@ — using it (v3-proven path)", NSStringFromClass([obj class])]);
        return obj;
    }
    return nil; // -> zeroed fallback (will crash in our harness — avoid by not calling)
}

static void run_drive_inline(void) {
    wa_marker(@"[drive] t8 drive start");

    int32_t *st = (int32_t *)g_slide_addr(kIndexStructVMA);
    if (!st) { wa_marker(@"[drive] struct NULL — abort"); return; }
    wa_marker([NSString stringWithFormat:@"[drive] struct @%p original: [+0]=%d [+4]=%d [+0x10]=%d", st, st[0], st[1], st[4]]);

    SEL s1 = NSSelectorFromString(@"fetchPendingRemovalCompanionDevicesForAccountUserJID:");
    SEL s2 = NSSelectorFromString(@"fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList:");
    Class c1 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
    Class c2 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
    if (!c1) c1 = wa_find_class(s1);
    if (!c2) c2 = wa_find_class(s2);

    id realSelf = wa_real_instance(c1 ?: c2);
    // v9: the table base IS the app-global slot (site 2: adrp/ldr x19,[0x107ceb520];
    // x20 table derives from it). v3 proved the slot holds a REAL NSMutableArray at
    // constructor time on some launches; v4-v8 hit nil-slot launches where driving
    // produces only a nil-table artifact (132741: fault 0x28 = idx0 with x20=0).
    // Poll up to 2.8s for a populated slot; if it never appears, exit cleanly (dud
    // run) — do NOT call with nil self (that yields a non-signature crash).
    for (int tick = 0; !realSelf && tick < 14; tick++) {
        usleep(200000);
        realSelf = wa_real_instance(c1 ?: c2);
        if (!realSelf) wa_marker([NSString stringWithFormat:@"[drive] poll %d: slot still nil", tick + 1]);
    }
    wa_marker([NSString stringWithFormat:@"[drive] receiver: %@ (%@)",
               realSelf ? NSStringFromClass([realSelf class]) : @"nil",
               realSelf ? @"REAL" : @"NO REAL SLOT — DUD RUN, no calls"]);

    if (!realSelf) {
        wa_marker(@"[drive] DUD: slot never populated in 2.8s — clean exit (app-self +3s crash will produce the .ips)");
        return;
    }
    id self1 = realSelf;
    id self2 = realSelf;

    // ===== CONTROL: call BOTH methods with the ORIGINAL (unpoisoned) struct =====
    // If the methods return normally, the harness + receiver are valid and the
    // ONLY variable left is the index value -> proves the poison is the cause.
    if (orig_fetchLinked && c2 && self2) {
        wa_marker(@"[ctrl] calling fetchLinkedAndPendingRemoval... (SITE 2, unpoisoned)");
        orig_fetchLinked(self2, s2, nil, nil);
        wa_marker(@"[ctrl] fetchLinkedAndPendingRemoval: RETURNED (no crash — harness OK)");
    }
    if (orig_fetchPending && c1 && self1) {
        wa_marker(@"[ctrl] calling fetchPendingRemoval... (SITE 1, unpoisoned)");
        orig_fetchPending(self1, s1, nil);
        wa_marker(@"[ctrl] fetchPendingRemoval: RETURNED (no crash — harness OK)");
    }
    wa_marker(@"[ctrl] CONTROL PASSED — both methods return normally unpoisoned");

    // ===== POISON: idx2 (+0x10) = 0x7FFFFFFF, then re-call =====
    int32_t saved = st[4];
    st[4] = 0x7FFFFFFF;
    wa_marker([NSString stringWithFormat:@"[drive] struct @%p poisoned: [+0x10]=%d (saved=%d)", st, st[4], saved]);

    // SITE 2 FIRST — prove fetchLinkedAndPendingRemoval... (0x101CA1634) before
    // site 1 so a site-1 crash can't mask it. (self may be nil — control proved
    // the methods run and return normally with nil self when unpoisoned.)
    if (orig_fetchLinked && c2) {
        wa_marker(@"[drive] calling fetchLinkedAndPendingRemoval... via orig (SITE 2, POISONED)");
        orig_fetchLinked(self2, s2, nil, nil);
        wa_marker(@"[drive] fetchLinkedAndPendingRemoval: RETURNED (no crash)");
    } else {
        wa_marker([NSString stringWithFormat:@"[drive] SKIP method2 (orig=%p c2=%p)", orig_fetchLinked, c2]);
    }

    if (orig_fetchPending && c1) {
        wa_marker(@"[drive] calling fetchPendingRemoval... via orig (SITE 1, POISONED)");
        orig_fetchPending(self1, s1, nil);
        wa_marker(@"[drive] fetchPendingRemoval: RETURNED (no crash)");
    } else {
        wa_marker([NSString stringWithFormat:@"[drive] SKIP method1 (orig=%p c1=%p)", orig_fetchPending, c1]);
    }

    st[4] = saved;
    wa_marker(@"[drive] t8 drive complete");
}

__attribute__((constructor))
static void waInit(void) {
    @autoreleasepool {
        wa_marker(@"=== waContainerFix ME73b v9 (t8 family, site2-first, poll-for-real-slot, control+poison) constructor ===");

        SEL s1 = NSSelectorFromString(@"fetchPendingRemovalCompanionDevicesForAccountUserJID:");
        SEL s2 = NSSelectorFromString(@"fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList:");
        for (int attempt = 0; attempt < 4 && !g_hooked; attempt++) {
            Class c1 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
            Class c2 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
            if (!c1) c1 = wa_find_class(s1);
            if (!c2) c2 = wa_find_class(s2);
            int done = 0;
            if (c1) {
                wa_swizzle(c1, s1, (IMP)hook_fetchPending, (void **)&orig_fetchPending);
                if (orig_fetchPending) done++;
            } else wa_marker(@"[init] class1 not loaded yet");
            if (c2) {
                wa_swizzle(c2, s2, (IMP)hook_fetchLinked, (void **)&orig_fetchLinked);
                if (orig_fetchLinked) done++;
            } else wa_marker(@"[init] class2 not loaded yet");
            wa_marker([NSString stringWithFormat:@"[init] attempt %d: hooked=%d", attempt + 1, done]);
            if (done == 2) { g_hooked = 1; break; }
            usleep(250000);
        }
        wa_marker(@"[init] ME73b constructor complete");

        // v7: drive IMMEDIATELY (v3-style — beats the app's +3s self-crash
        // window), polling every 200ms until the app-global slot populates.
        // dispatch_after(+3s) lost the race in v6 — never use a long delay.
        run_drive_inline();
    }
}
