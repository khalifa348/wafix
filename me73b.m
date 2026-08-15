// ME73b (t8) test dylib — 2 NEW companion-device family sites:
//   fetchPendingRemovalCompanionDevicesForAccountUserJID:
//       @0x1001A4DD4 (unchecked idx @ 0x1001A4E18: ldrsw x8,[x8,#0x10] -> ldr x5,[x21,x8])
//   fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList:
//       @0x101CA1634 (unchecked idx @ 0x101CA1684: ldrsw x8,[x8,#0x10] -> ldr x26,[x20,x8])
// Both read the SAME shared 3-word index struct (thunk 0x1000242A4 -> &0x107d0744c,
// __DATA writable; idx0@+0, idx1@+4, UNCHECKED idx2@+0x10) — same t7 bug class.
// Drive: write 0x7FFFFFFF into struct+0x10 (slide-adjusted), call orig on crafted
// instance -> table[0x7FFFFFFF] -> garbage pointer -> downstream SIGSEGV.
// Reuses ME73 lessons: FAST constructor, inline drive on main thread, marker-only logging.

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

// --- shared global index struct (image-relative) ---
static const uint64_t kIndexStructRel = 0x7d0744c; // 0x107d0744c - 0x100000000

static void *g_struct_slide(void) {
    uintptr_t slide = _dyld_get_image_vmaddr_slide(0); // main executable
    return (void *)(slide + kIndexStructRel);
}

// --- hooks: signatures ---
// fetchPendingRemovalCompanionDevicesForAccountUserJID:(id)jid
static void (*orig_fetchPending)(id, SEL, id);
static void hook_fetchPending(id self, SEL _cmd, id jid) {
    wa_marker([NSString stringWithFormat:@"[hook] fetchPendingRemoval... jid=%@ self=%@", jid, NSStringFromClass([self class])]);
    orig_fetchPending(self, _cmd, jid);
}

// fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:(id)jid currentDeviceList:(id)list
static void (*orig_fetchLinked)(id, SEL, id, id);
static void hook_fetchLinked(id self, SEL _cmd, id jid, id list) {
    wa_marker([NSString stringWithFormat:@"[hook] fetchLinkedAndPending... jid=%@ list=%@ self=%@", jid, list, NSStringFromClass([self class])]);
    orig_fetchLinked(self, _cmd, jid, list);
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

// find class that actually implements the selector (runtime scan, no static PAC issues)
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

static void run_drive_inline(void) {
    wa_marker(@"[drive] t8 drive start (struct idx2 = 0x7FFFFFFF)");

    // 1. locate shared index struct, poke idx2
    int32_t *st = (int32_t *)g_struct_slide();
    if (!st) { wa_marker(@"[drive] struct NULL — abort"); return; }
    wa_marker([NSString stringWithFormat:@"[drive] struct @%p before: [+0]=%d [+4]=%d [+0x10]=%d", st, st[0], st[1], st[4]]);
    st[4] = 0x7FFFFFFF;  // +0x10 slot
    wa_marker([NSString stringWithFormat:@"[drive] struct @%p after:  [+0x10]=%d", st, st[4]]);

    SEL s1 = NSSelectorFromString(@"fetchPendingRemovalCompanionDevicesForAccountUserJID:");
    SEL s2 = NSSelectorFromString(@"fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList:");
    Class c1 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
    Class c2 = NSClassFromString(@"WAOwnDeviceManagerMain");
    if (!c1) c1 = wa_find_class(s1);
    if (!c2) c2 = wa_find_class(s2);
    wa_marker([NSString stringWithFormat:@"[drive] class1=%@ class2=%@", c1 ? NSStringFromClass(c1) : @"?", c2 ? NSStringFromClass(c2) : @"?"]);

    // 2. drive method 1
    if (orig_fetchPending && c1) {
        __unsafe_unretained id selfObj = class_createInstance(c1, 0);
        wa_marker(@"[drive] calling fetchPendingRemoval... (crafted instance)");
        orig_fetchPending(selfObj, s1, nil);
        wa_marker(@"[drive] fetchPendingRemoval: RETURNED (no crash)");
    } else {
        wa_marker([NSString stringWithFormat:@"[drive] SKIP method1 (orig=%p c1=%p)", orig_fetchPending, c1]);
    }

    // 3. drive method 2
    if (orig_fetchLinked && c2) {
        __unsafe_unretained id selfObj = class_createInstance(c2, 0);
        wa_marker(@"[drive] calling fetchLinkedAndPendingRemoval... (crafted instance)");
        orig_fetchLinked(selfObj, s2, nil, nil);
        wa_marker(@"[drive] fetchLinkedAndPendingRemoval: RETURNED (no crash)");
    } else {
        wa_marker([NSString stringWithFormat:@"[drive] SKIP method2 (orig=%p c2=%p)", orig_fetchLinked, c2]);
    }

    wa_marker(@"[drive] t8 drive complete");
}

__attribute__((constructor))
static void waInit(void) {
    @autoreleasepool {
        wa_marker(@"=== waContainerFix ME73b (t8 companion-device family) constructor ===");

        for (int attempt = 0; attempt < 4; attempt++) {
            if (!g_hooked) {
                SEL s1 = NSSelectorFromString(@"fetchPendingRemovalCompanionDevicesForAccountUserJID:");
                SEL s2 = NSSelectorFromString(@"fetchLinkedAndPendingRemovalCompanionDevicesForAccountUserJID:currentDeviceList:");
                Class c1 = NSClassFromString(@"WAOwnDeviceStorageManagerMain");
                Class c2 = NSClassFromString(@"WAOwnDeviceManagerMain");
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
                if (done == 2) g_hooked = 1;
            }
            wa_marker([NSString stringWithFormat:@"[init] attempt %d: hooked=%d", attempt + 1, g_hooked]);
            if (g_hooked) break;
            usleep(250000);
        }
        wa_marker(@"[init] ME73b constructor complete");

        run_drive_inline();
    }
}
