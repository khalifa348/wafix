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

// real instance from the app's own global (the method loads x20 from this exact slot)
static id wa_real_instance(Class want) {
    __unsafe_unretained id *slot = (__unsafe_unretained id *)g_slide_addr(kSingletonVMA);
    if (!slot) return nil;
    id obj = *slot;
    if (obj && want && object_isClass(obj) == NO && [obj isKindOfClass:want]) return obj;
    // try to find any live instance of want among classes' registered instances is
    // impossible without private runtime — fall back to singleton selector patterns
    if (obj && [obj respondsToSelector:@selector(isKindOfClass:)]) return obj; // best effort
    return nil;
}

static void run_drive_inline(void) {
    wa_marker(@"[drive] t8 drive start (struct idx2 = 0x7FFFFFFF)");

    int32_t *st = (int32_t *)g_slide_addr(kIndexStructVMA);
    if (!st) { wa_marker(@"[drive] struct NULL — abort"); return; }
    wa_marker([NSString stringWithFormat:@"[drive] struct @%p before: [+0]=%d [+4]=%d [+0x10]=%d", st, st[0], st[1], st[4]]);
    st[4] = 0x7FFFFFFF;  // +0x10 slot
    wa_marker([NSString stringWithFormat:@"[drive] struct @%p after:  [+0x10]=%d", st, st[4]]);

    SEL s1 = NSSelectorFromString(@"fetchPendingRemovalCompanionDevicesForAccountUserJID:");
    SEL s2 = NSSelectorFromString(@"fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList:");
    Class c1 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
    Class c2 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
    if (!c1) c1 = wa_find_class(s1);
    if (!c2) c2 = wa_find_class(s2);

    // REAL instance from the app's own global slot
    id realSelf = wa_real_instance(c1 ?: c2);
    wa_marker([NSString stringWithFormat:@"[drive] singleton global @%p -> %@ (%@)",
               g_slide_addr(kSingletonVMA), realSelf ? NSStringFromClass([realSelf class]) : @"nil",
               realSelf ? @"REAL" : @"missing — will use zeroed fallback"]);

    id self1 = realSelf;
    id self2 = realSelf;
    if (!self1 && c1) {
        self1 = (__bridge id)calloc(1, class_getInstanceSize(c1)); // zeroed — no garbage C++ ivars
        wa_marker(@"[drive] using ZEROED fallback instance for method1");
    }
    if (!self2 && c2) {
        self2 = (__bridge id)calloc(1, class_getInstanceSize(c2));
        wa_marker(@"[drive] using ZEROED fallback instance for method2");
    }

    if (orig_fetchPending && c1 && self1) {
        wa_marker(@"[drive] calling fetchPendingRemoval... via orig");
        orig_fetchPending(self1, s1, nil);
        wa_marker(@"[drive] fetchPendingRemoval: RETURNED (no crash)");
    } else {
        wa_marker([NSString stringWithFormat:@"[drive] SKIP method1 (orig=%p c1=%p self1=%p)", orig_fetchPending, c1, self1]);
    }

    if (orig_fetchLinked && c2 && self2) {
        wa_marker(@"[drive] calling fetchLinkedAndPendingRemoval... via orig");
        orig_fetchLinked(self2, s2, nil, nil);
        wa_marker(@"[drive] fetchLinkedAndPendingRemoval: RETURNED (no crash)");
    } else {
        wa_marker([NSString stringWithFormat:@"[drive] SKIP method2 (orig=%p c2=%p self2=%p)", orig_fetchLinked, c2, self2]);
    }

    wa_marker(@"[drive] t8 drive complete");
}

__attribute__((constructor))
static void waInit(void) {
    @autoreleasepool {
        wa_marker(@"=== waContainerFix ME73b v3 (t8 companion-device family) constructor ===");

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

        run_drive_inline();
    }
}
