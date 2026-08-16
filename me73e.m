// ME73e (t8 re-validation) — site-1 index ladder WITH controls.
//
// WHY: ME73d proved site-2's 3/3 REDs are synthetic-NSNull artifacts (control
// idx2=0 crashed identically to the 0x7FFFFFFF poison — the NSNull entries don't
// respond to the method's internal selectors, so ANY index crashes). The same
// rigor must now settle site-1 (fetchPendingRemovalCompanionDevicesForAccountUserJID:,
// v3.1-era REDs 123349/124613, doesNotRecognizeSelector at 0x1a4e58).
//
// ME73e drives site-1 through the SAME harness (synthetic-slot fallback + REAL
// app-global when present) with an index LADDER:
//   0 (control) -> 5 (control) -> 100 -> 1000 -> 100000 -> 200000 -> 0x7FFFFFFF (anchor)
// Each step logged before/after. Verdict:
//   * controls crash          -> synthetic/table-content artifact -> site-1 RETRACTED
//   * controls pass, ladder x -> genuine index-driven OOB at realistic value x
//   * only 0x7FFFFFFF crashes -> real OOB but unrealistic value (max-int only)
// The drive logs whether the slot was REAL or synthetic at drive time — the key
// discriminator for interpreting the v3.1 REDs.

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

// site-1 hook: fetchPendingRemovalCompanionDevicesForAccountUserJID: (ONE arg)
static void (*orig_fetchPending)(id, SEL, id);
static void hook_fetchPending(id self, SEL _cmd, id jid) {
    wa_marker([NSString stringWithFormat:@"[hook] fetchPendingRemoval... self=%@", NSStringFromClass([self class])]);
    orig_fetchPending(self, _cmd, jid);
}

static void wa_swizzle(Class cls, SEL sel, IMP newImp, void **origOut) {
    if (*origOut) return;
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
static NSMutableArray *g_synthetic = nil;
static BOOL g_synthetic_slot = NO;

static id wa_real_instance(Class want) {
    __unsafe_unretained id *slot = (__unsafe_unretained id *)g_slide_addr(kSingletonVMA);
    if (!slot) return nil;
    id obj = *slot;
    if (obj && object_isClass(obj) == NO) {
        g_synthetic_slot = NO;
        wa_marker([NSString stringWithFormat:@"[inst] app global is %@ — using it (REAL path)", NSStringFromClass([obj class])]);
        return obj;
    }
    g_synthetic_slot = YES;
    g_synthetic = [[NSMutableArray alloc] initWithCapacity:256];
    for (int i = 0; i < 256; i++) [g_synthetic addObject:[NSNull null]];
    *slot = g_synthetic;
    wa_marker(@"[inst] slot EMPTY — WROTE synthetic NSMutableArray (256 NSNull) into app global");
    return g_synthetic;
}

// The index ladder: 0/5 = controls (valid in-bounds reads), then realistic
// server-plausible device-list sizes, then the max-int anchor.
static const int32_t kIndexLadder[] = {0, 5, 100, 1000, 100000, 200000, 0x7FFFFFFF};
static const int kLadderSize = 7;

static void run_drive_inline(void) {
    wa_marker(@"[drive] ME73e site-1 index ladder start (controls 0/5 first)");
    int32_t *st = (int32_t *)g_slide_addr(kIndexStructVMA);
    if (!st) { wa_marker(@"[drive] struct NULL — abort"); return; }
    wa_marker([NSString stringWithFormat:@"[drive] struct @%p original: [+0]=%d [+4]=%d [+0x10]=%d", st, st[0], st[1], st[4]]);

    SEL s1 = NSSelectorFromString(@"fetchPendingRemovalCompanionDevicesForAccountUserJID:");
    Class c1 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
    if (!c1) c1 = wa_find_class(s1);
    if (!c1 || !orig_fetchPending) { wa_marker([NSString stringWithFormat:@"[drive] SKIP (orig=%p c1=%p)", orig_fetchPending, c1]); return; }

    id realSelf = wa_real_instance(c1);
    wa_marker([NSString stringWithFormat:@"[drive] receiver: %@ (%@)", NSStringFromClass([realSelf class]),
               g_synthetic_slot ? @"SYNTHETIC (v10 wrote own array)" : @"REAL app global"]);

    int32_t saved = st[4];
    for (int i = 0; i < kLadderSize; i++) {
        st[4] = kIndexLadder[i];
        wa_marker([NSString stringWithFormat:@"[drive] STEP %d/%d: idx2=%d ...", i + 1, kLadderSize, kIndexLadder[i]]);
        orig_fetchPending(realSelf, s1, nil);
        wa_marker([NSString stringWithFormat:@"[drive] STEP %d/%d: idx2=%d RETURNED (no crash)", i + 1, kLadderSize, kIndexLadder[i]]);
    }
    st[4] = saved;
    wa_marker(@"[drive] ME73e ladder complete — NO crash at any index");
}

__attribute__((constructor))
static void waInit(void) {
    @autoreleasepool {
        wa_marker(@"=== waContainerFix ME73e (site-1 index LADDER with controls) constructor ===");

        SEL s1 = NSSelectorFromString(@"fetchPendingRemovalCompanionDevicesForAccountUserJID:");
        for (int attempt = 0; attempt < 4 && !g_hooked; attempt++) {
            Class c1 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
            if (!c1) c1 = wa_find_class(s1);
            if (c1) {
                wa_swizzle(c1, s1, (IMP)hook_fetchPending, (void **)&orig_fetchPending);
                if (orig_fetchPending) g_hooked = 1;
            } else {
                wa_marker(@"[init] class not loaded yet");
            }
            wa_marker([NSString stringWithFormat:@"[init] attempt %d: hooked=%d", attempt + 1, g_hooked]);
            if (g_hooked) break;
            usleep(250000);
        }
        wa_marker(@"[init] ME73e constructor complete");

        run_drive_inline();
    }
}
