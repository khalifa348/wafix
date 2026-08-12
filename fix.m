// waContainerFix v14 — v10 + lazy interpose init (reals valid pre-constructor)
// + resolver rewritten: no class_getInstanceMethod/class_getMethodImplementation/
// os_log inside resolver (all three re-enter resolveMethod_locked -> infinite
// recursion -> stack overflow. ME40 crash 03:18:59: 6+ alternating frames).
// v11 = v10 dyld-interpose anti-detection + thread-local recursion guards +
// direct method-list scans + marker-only resolver logging.
// v9 (ME39) proven: os_log flood GONE (3 unique resolves vs 1518), resolver
//   healthy, markers de-duped. BUT app STILL self-exits ~2min after launch,
//   silently, no crash report, no jetsam, no watchdog — and it RELAUNCHED
//   itself (4 constructor blocks in marker = SpringBoard relaunch after each
//   silent exit).
// ROOT CAUSE (static analysis of pristine binary): WhatsApp anti-tamper.
//   Strings found: WASDEKmpSyncdIncomingAntiTamperingValidator,
//   WASDEKmpSyncdAntiTamperingLoggingHelper(+Companion), WASDEAntiTamperingData,
//   __dyld_image_count, __dyld_get_image_name, __dyld_get_image_header,
//   _dyld_register_func_for_add_image (dyld load callbacks!), dladdr, sysctl,
//   isJailbrokenDevice + "It appears that your device is jailbroken" UI text.
//   The app registers a dyld add-image callback, enumerates loaded images,
//   spots libwaContainerFix.dylib, and calls exit() silently.
// v10: hide our dylib from dyld enumeration via DYLD_INTERPOSE:
//   - _dyld_image_count        -> real count - 1
//   - _dyld_get_image_name     -> index shifted past our image
//   - _dyld_get_image_header   -> same shift
//   - _dyld_register_func_for_add_image / _remove -> swallow callbacks
//   - dladdr                   -> fail for addresses inside our dylib
//   Keeps v9 resolver + blacklist + de-duped markers.
// v7 died in constructor: wa_swizzle(..., NULL) dereferenced origOut unconditionally
//   -> SIGSEGV 0.39s after constructor (marker file proved: crash between
//   'constructor' marker and 'swizzled resolveInstanceMethod:' marker).
// v8: guard origOut before deref. v7's metaclass fix + re-entry guards retained.
// v5 proved: country-DB fix WORKS (COUNTRY-MATCH logs firing, real TSV found, app
//   reached FOREGROUND). Next wall: '-[WAAppPreferences setBackgroundAppRefreshStatus:]:
//   unrecognized selector' 4s after launch — WAAppPreferences class lives in
//   SharedModules (FairPlay), selector only in main binary -> category method not
//   attaching (same family as ME28/ME34 country-DB placeholder crash).
// v6: swizzle +[NSObject resolveInstanceMethod:] / resolveClassMethod: to
//   synthesize no-op methods for ANY missing selector. Kills the whole family at
//   once instead of whack-a-mole. Logs every synthesis.

#import <Foundation/Foundation.h>
#import <os/log.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>

// forward decl (wa_marker defined later in file)
static void wa_marker(NSString *line);

// ---------- v10: dyld interpose (anti-tamper evasion) ----------
// Real function pointers captured from libdyld. MUST be captured lazily on
// first use (NOT only in the constructor): dyld applies the __interpose
// section the moment our image loads — BEFORE the constructor runs — so
// WhatsApp's +load methods can hit our fakes with uninitialized reals
// (v11 lesson: v10's constructor-only init left reals NULL -> dladdr failed
// for the whole process -> system frameworks broke -> resolver recursion).
static uint32_t (*real_dyld_image_count)(void);
static const char *(*real_dyld_get_image_name)(uint32_t index);
static const struct mach_header *(*real_dyld_get_image_header)(uint32_t index);
static void (*real_dyld_register_func_for_add_image)(void (*)(const struct mach_header *mh, intptr_t vmaddr_slide));
static void (*real_dyld_register_func_for_remove_image)(void (*)(const struct mach_header *mh, intptr_t vmaddr_slide));
static int (*real_dladdr)(const void *, Dl_info *);

static const struct mach_header *g_ourHeader = NULL;
static uint32_t g_ourIndex = UINT32_MAX;
static int g_realsInited = 0;

static void wa_antiDetectInit(void) {
    if (g_realsInited) return;
    // v14 FIX (crash: re-entrancy flood): set the guard FIRST. v13 set it at
    // the END -> wa_marker -> Foundation file I/O -> internal dladdr()
    // (interposed!) -> wa_fake_dladdr -> wa_antiDetectInit re-entered with
    // flag still 0 -> wrote "antiDetect: reals" marker recursively, init
    // NEVER completed (no "ourHeader" line ever), app died silently ~60-90s
    // (tamper timer, no crash report). With the guard set first, any
    // interposed call during init just runs the fakes with partially-set
    // reals (safe: they null-check before use).
    g_realsInited = 1;
    // v13: capture reals via dlsym(RTLD_DEFAULT, ...). Our fake replacements
    // are STATIC functions (never exported), so RTLD_DEFAULT finds the REAL
    // exports in libdyld. dyld4's dlsym is interpose-aware: it returns the
    // ORIGINAL definition for interposed symbols.
    // (v11 lesson: RTLD_NEXT from our dylib = SILENT DEATH, we're the last
    // image in load order and there's no "next" — dyld4 aborts the process.
    // v12 lesson: dlopen("/usr/lib/libdyld.dylib") returned NULL on iOS 26
    // from inside a constructor — reals stayed NULL -> fakes returned
    // count=0/dladdr=0 process-wide -> system breakage -> silent death.)
    real_dyld_image_count = (uint32_t (*)(void))dlsym(RTLD_DEFAULT, "_dyld_image_count");
    real_dyld_get_image_name = (const char *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    real_dyld_get_image_header = (const struct mach_header *(*)(uint32_t))dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    real_dyld_register_func_for_add_image = (void (*)(void (*)(const struct mach_header *, intptr_t)))dlsym(RTLD_DEFAULT, "_dyld_register_func_for_add_image");
    real_dyld_register_func_for_remove_image = (void (*)(void (*)(const struct mach_header *, intptr_t)))dlsym(RTLD_DEFAULT, "_dyld_register_func_for_remove_image");
    real_dladdr = (int (*)(const void *, Dl_info *))dlsym(RTLD_DEFAULT, "dladdr");
    wa_marker([NSString stringWithFormat:@"antiDetect: reals count=%p name=%p hdr=%p dladdr=%p",
               real_dyld_image_count, real_dyld_get_image_name,
               real_dyld_get_image_header, real_dladdr]);
    // our own header via dladdr on our code
    Dl_info info;
    if (real_dladdr && real_dladdr((const void *)&wa_antiDetectInit, &info)) {
        g_ourHeader = info.dli_fbase;
    }
    // our index in the real dyld list
    if (g_ourHeader && real_dyld_image_count && real_dyld_get_image_header) {
        uint32_t n = real_dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            if (real_dyld_get_image_header(i) == g_ourHeader) { g_ourIndex = i; break; }
        }
    }
    wa_marker([NSString stringWithFormat:@"antiDetect: ourHeader=%p ourIndex=%u count=%u",
               g_ourHeader, g_ourIndex, real_dyld_image_count ? real_dyld_image_count() : 0]);
}

static uint32_t wa_fake_dyld_image_count(void) {
    wa_antiDetectInit();
    uint32_t n = real_dyld_image_count ? real_dyld_image_count() : 0;
    return (g_ourIndex < n) ? n - 1 : n;
}

static const char *wa_fake_dyld_get_image_name(uint32_t index) {
    wa_antiDetectInit();
    if (g_ourIndex != UINT32_MAX && index >= g_ourIndex) index++;
    return real_dyld_get_image_name ? real_dyld_get_image_name(index) : "";
}

static const struct mach_header *wa_fake_dyld_get_image_header(uint32_t index) {
    wa_antiDetectInit();
    if (g_ourIndex != UINT32_MAX && index >= g_ourIndex) index++;
    return real_dyld_get_image_header ? real_dyld_get_image_header(index) : NULL;
}

// swallow add/remove image callbacks — the anti-tamper never learns of our dylib
static void wa_fake_dyld_register_func_for_add_image(void (*func)(const struct mach_header *, intptr_t)) {
    (void)func;  // deliberately drop
}

static void wa_fake_dyld_register_func_for_remove_image(void (*func)(const struct mach_header *, intptr_t)) {
    (void)func;  // deliberately drop
}

// dladdr: return 0 (not found) when the address belongs to our dylib
static int wa_fake_dladdr(const void *addr, Dl_info *info) {
    wa_antiDetectInit();
    if (!real_dladdr) return 0;
    if (real_dladdr(addr, info) == 0) return 0;
    if (info && info->dli_fbase == g_ourHeader) return 0;
    return 1;
}

// DYLD_INTERPOSE section (__DATA,__interpose) — same shape as the SDK macro
#define WA_INTERPOSE(replacement, replacee) \
    __attribute__((used)) static struct { const void *replacement; const void *replacee; } \
    _wa_interpose_##replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&replacement, (const void *)(unsigned long)&replacee };

WA_INTERPOSE(wa_fake_dyld_image_count, _dyld_image_count)
WA_INTERPOSE(wa_fake_dyld_get_image_name, _dyld_get_image_name)
WA_INTERPOSE(wa_fake_dyld_get_image_header, _dyld_get_image_header)
WA_INTERPOSE(wa_fake_dyld_register_func_for_add_image, _dyld_register_func_for_add_image)
WA_INTERPOSE(wa_fake_dyld_register_func_for_remove_image, _dyld_register_func_for_remove_image)
WA_INTERPOSE(wa_fake_dladdr, dladdr)

static os_log_t wa_log(void) {
    static os_log_t l;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        l = os_log_create("com.wafix", "dylib");
    });
    return l;
}

// ---------- v6: universal missing-selector synthesis ----------
// Called whenever a class fails to find an instance method. We add a no-op
// implementation so the app keeps running instead of NSInvalidArgumentException.
// v7 FIX: v6 added to object_getClass(self) (metaclass) -> method never found
//   -> resolveInstanceMethod: re-entered -> infinite recursion -> SIGSEGV.
//   Now: add to self (the class), guard re-entry, skip classes with real
//   forwarding (NSProxy-style), return nil from no-op.
// v9: blacklist os_log's private string-encoding selectors (encodeWithOSLogCoder*)
//   — v8 flooded: 1518 resolves of NSTaggedPointerString -encodeWithOSLogCoder:
//   (os_log encodes every NSString arg through it). Stock runtime returns NO
//   (default forwarding) and works; we must do the same INSTANTLY (no log, no
//   marker) or we break os_log and churn main-thread file I/O.
//   Also: markers now de-duplicated — only NEW (class, selector) combos are
//   written, so a hot selector can't stall launch with 1000s of file writes.

static NSString *wa_markerPath(void) {
    return [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wafix_marker.txt"];
}

static void wa_marker(NSString *line) {
    @autoreleasepool {
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:wa_markerPath()];
        if (!fh) {
            [[NSFileManager defaultManager] createFileAtPath:wa_markerPath() contents:nil attributes:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:wa_markerPath()];
        }
        if (fh) {
            [fh seekToEndOfFile];
            [fh writeData:[[line stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding]];
            [fh closeFile];
        }
    }
}

// de-dup: only log a (class, selector) combo once per run
static NSMutableSet *g_markerSeen = nil;
static void wa_markerOnce(NSString *line) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{ g_markerSeen = [NSMutableSet set]; });
    if ([g_markerSeen containsObject:line]) return;
    [g_markerSeen addObject:line];
    wa_marker(line);
}

// os_log private encoding path — hands off instantly (stock behavior)
static BOOL wa_isOsLogSelector(const char *sel) {
    if (!sel) return NO;
    if (strstr(sel, "encodeWithOSLogCoder") != NULL) return YES;
    return NO;
}

static id wa_noop(id self, SEL _cmd) { return nil; }

// v11: NEVER call class_getInstanceMethod / class_getMethodImplementation
// inside the resolver — those trigger resolveMethod_locked -> our swizzle ->
// infinite recursion (ME40 crash 03:18:59: 6+ alternating frames, stack
// overflow -> KERN_PROTECTION_FAILURE in localtime_r/os_log). Use
// class_copyMethodList (direct read, no resolution) + class_addMethod only.
static _Thread_local BOOL wa_resolvingInst = NO;
static _Thread_local BOOL wa_resolvingCls = NO;

// does the class DIRECTLY define forwardInvocation:? (no resolution trigger)
static BOOL wa_hasRealForwardingDirect(Class cls) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    if (!methods) return NO;
    SEL fwd = sel_registerName("forwardInvocation:");
    BOOL found = NO;
    for (unsigned int i = 0; i < count; i++) {
        if (method_getName(methods[i]) == fwd) { found = YES; break; }
    }
    free(methods);
    return found;
}

// does the class DIRECTLY define this selector? (no resolution trigger)
static BOOL wa_hasMethodDirect(Class cls, SEL sel) {
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    if (!methods) return NO;
    BOOL found = NO;
    for (unsigned int i = 0; i < count; i++) {
        if (method_getName(methods[i]) == sel) { found = YES; break; }
    }
    free(methods);
    return found;
}

static BOOL wa_resolveInstance(id self, SEL _cmd, SEL name) {
    if (wa_resolvingInst) return NO;   // recursion guard (thread-local)
    Class cls = (Class)self;
    const char *clsName = class_getName(cls);
    const char *selName = sel_getName(name);
    // v9: os_log private path — stock behavior, instant NO, no log/marker churn
    if (wa_isOsLogSelector(selName)) return NO;
    // v11: NO os_log here — os_log's encoding path can itself trigger
    // class_respondsToSelector -> resolveMethod_locked -> re-entry (ME40
    // crash stack showed exactly that). Marker file is our ground truth.
    wa_markerOnce([NSString stringWithFormat:@"RESOLVE-INST %s -%s", clsName, selName]);
    if (wa_hasRealForwardingDirect(cls)) {
        return NO;
    }
    wa_resolvingInst = YES;
    BOOL added = class_addMethod(cls, name, (IMP)wa_noop, "@@:");
    wa_resolvingInst = NO;
    if (!added && !wa_hasMethodDirect(cls, name)) {
        return NO;
    }
    return YES;
}

static BOOL wa_resolveClass(id self, SEL _cmd, SEL name) {
    if (wa_resolvingCls) return NO;    // recursion guard (thread-local)
    Class meta = object_getClass(self);
    const char *clsName = class_getName(meta);
    const char *selName = sel_getName(name);
    // v9: os_log private path — stock behavior, instant NO
    if (wa_isOsLogSelector(selName)) return NO;
    // v11: NO os_log here (re-entry vector, see wa_resolveInstance)
    wa_markerOnce([NSString stringWithFormat:@"RESOLVE-CLASS %s +%s", clsName, selName]);
    if (wa_hasRealForwardingDirect(meta)) {
        return NO;
    }
    wa_resolvingCls = YES;
    BOOL added = class_addMethod(meta, name, (IMP)wa_noop, "@@:");
    wa_resolvingCls = NO;
    if (!added && !wa_hasMethodDirect(meta, name)) {
        return NO;
    }
    return YES;
}

// ---------- v2: nil-guard +[NSURL fileURLWithPath:] ----------
static IMP orig_fileURLWithPath = NULL;
static IMP orig_fileURLWithPathIsDir = NULL;

static id wa_fileURLWithPath(id self, SEL _cmd, NSString *path) {
    if (path == nil) {
        os_log_info(wa_log(), "fileURLWithPath:nil GUARDED -> home");
        path = NSHomeDirectory();
    }
    return ((id (*)(id, SEL, NSString *))orig_fileURLWithPath)(self, _cmd, path);
}

static id wa_fileURLWithPathIsDir(id self, SEL _cmd, NSString *path, BOOL isDir) {
    if (path == nil) {
        os_log_info(wa_log(), "fileURLWithPath:isDirectory:nil GUARDED -> home");
        path = NSHomeDirectory();
    }
    return ((id (*)(id, SEL, NSString *, BOOL))orig_fileURLWithPathIsDir)(self, _cmd, path, isDir);
}

// ---------- v2: fake the app-group container ----------
static IMP orig_containerURL = NULL;
static id wa_containerURL(id self, SEL _cmd, NSString *group) {
    os_log_info(wa_log(), "containerURL(%@) -> NSHomeDirectory", group);
    return [NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES];
}

// ---------- v3: country-DB synthesis ----------
static NSDictionary *g_fakeCountryDB = nil;
static NSString *g_realTsv = nil;

static BOOL wa_isCountryPath(NSString *p) {
    if (!p) return NO;
    NSString *low = p.lowercaseString;
    return [low containsString:@"countr"] || [low containsString:@"country"];
}

static NSString *wa_realTsv(void) {
    if (g_realTsv) return g_realTsv;
    NSString *tsvPath = [[NSBundle mainBundle] pathForResource:@"countries"
                                                        ofType:@"tsv"
                                                   inDirectory:@"Frameworks/SharedModules.framework"];
    if (!tsvPath) {
        NSString *fw = [[[NSBundle mainBundle] bundlePath]
            stringByAppendingPathComponent:@"Frameworks/SharedModules.framework"];
        tsvPath = [fw stringByAppendingPathComponent:@"countries.tsv"];
    }
    NSError *err = nil;
    g_realTsv = [NSString stringWithContentsOfFile:tsvPath encoding:NSUTF8StringEncoding error:&err];
    if (!g_realTsv) os_log_fault(wa_log(), "countries.tsv unreadable: %{public}@", err.localizedDescription);
    else os_log_info(wa_log(), "loaded real countries.tsv: %lu chars", (unsigned long)g_realTsv.length);
    return g_realTsv;
}

static NSDictionary *wa_buildCountryDB(void) {
    if (g_fakeCountryDB) return g_fakeCountryDB;
    NSString *txt = wa_realTsv();
    if (!txt) return nil;
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    for (NSString *line in [txt componentsSeparatedByString:@"\n"]) {
        NSArray *f = [line componentsSeparatedByString:@"\t"];
        if (f.count < 3) continue;
        NSString *iso = f[0];
        if (iso.length != 2) continue;
        out[iso] = @{
            @"cc": f[1],
            @"itu": f[2],
            @"iso": iso,
        };
    }
    g_fakeCountryDB = out;
    os_log_info(wa_log(), "synthesized country DB: %lu entries", (unsigned long)out.count);
    return out;
}

// ---------- v5: fileExistsAtPath discovery ----------
static IMP orig_fileExists = NULL;
static IMP orig_fileExistsIsDir = NULL;
static int g_existsLogCount = 0;

static BOOL wa_fileExists(id self, SEL _cmd, NSString *path) {
    if (path && g_existsLogCount < 60) {
        g_existsLogCount++;
        os_log_info(wa_log(), "fileExistsAtPath: %{public}@", path);
    }
    if (wa_isCountryPath(path)) {
        os_log_info(wa_log(), "fileExistsAtPath COUNTRY-MATCH -> YES (synthesize)");
        return YES;
    }
    return ((BOOL (*)(id, SEL, NSString *))orig_fileExists)(self, _cmd, path);
}

static BOOL wa_fileExistsIsDir(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    if (path && g_existsLogCount < 60) {
        g_existsLogCount++;
        os_log_info(wa_log(), "fileExistsAtPath:isDirectory: %{public}@", path);
    }
    if (wa_isCountryPath(path)) {
        os_log_info(wa_log(), "fileExistsAtPath:isDirectory: COUNTRY-MATCH -> YES (synthesize)");
        if (isDir) *isDir = NO;
        return YES;
    }
    return ((BOOL (*)(id, SEL, NSString *, BOOL *))orig_fileExistsIsDir)(self, _cmd, path, isDir);
}

// ---------- v5: NSString file readers ----------
static IMP orig_strFile = NULL;
static NSString *wa_strFile(id self, SEL _cmd, NSString *path, NSStringEncoding enc, NSError **err) {
    if (wa_isCountryPath(path)) {
        os_log_info(wa_log(), "stringWithContentsOfFile COUNTRY-MATCH -> real TSV");
        if (err) *err = nil;
        return wa_realTsv();
    }
    return ((NSString *(*)(id, SEL, NSString *, NSStringEncoding, NSError **))orig_strFile)(self, _cmd, path, enc, err);
}

static IMP orig_strInitFile = NULL;
static NSString *wa_strInitFile(id self, SEL _cmd, NSString *path, NSStringEncoding enc, NSError **err) {
    if (wa_isCountryPath(path)) {
        os_log_info(wa_log(), "initWithContentsOfFile COUNTRY-MATCH -> real TSV");
        if (err) *err = nil;
        return wa_realTsv();
    }
    return ((NSString *(*)(id, SEL, NSString *, NSStringEncoding, NSError **))orig_strInitFile)(self, _cmd, path, enc, err);
}

// ---------- v5: NSData readers ----------
static IMP orig_dataFile = NULL;
static NSData *wa_dataFile(id self, SEL _cmd, NSString *path) {
    if (wa_isCountryPath(path)) {
        os_log_info(wa_log(), "dataWithContentsOfFile COUNTRY-MATCH -> real TSV data");
        return [wa_realTsv() dataUsingEncoding:NSUTF8StringEncoding];
    }
    return ((NSData *(*)(id, SEL, NSString *))orig_dataFile)(self, _cmd, path);
}

static IMP orig_dataURL = NULL;
static NSData *wa_dataURL(id self, SEL _cmd, NSURL *url) {
    if (wa_isCountryPath(url.path)) {
        os_log_info(wa_log(), "dataWithContentsOfURL COUNTRY-MATCH -> real TSV data");
        return [wa_realTsv() dataUsingEncoding:NSUTF8StringEncoding];
    }
    return ((NSData *(*)(id, SEL, NSURL *))orig_dataURL)(self, _cmd, url);
}

static IMP orig_dataInitFile = NULL;
static NSData *wa_dataInitFile(id self, SEL _cmd, NSString *path) {
    if (wa_isCountryPath(path)) {
        os_log_info(wa_log(), "initWithContentsOfFile(NSData) COUNTRY-MATCH -> real TSV data");
        return [wa_realTsv() dataUsingEncoding:NSUTF8StringEncoding];
    }
    return ((NSData *(*)(id, SEL, NSString *))orig_dataInitFile)(self, _cmd, path);
}

// ---------- v5: error:-variant dictionary/array readers ----------
static IMP orig_dictURLErr = NULL;
static NSDictionary *wa_dictURLErr(id self, SEL _cmd, NSURL *url, NSError **err) {
    id r = ((id (*)(id, SEL, NSURL *, NSError **))orig_dictURLErr)(self, _cmd, url, err);
    if (!r && wa_isCountryPath(url.path)) {
        os_log_info(wa_log(), "dictionaryWithContentsOfURL:error: COUNTRY-MATCH -> synthesized DB");
        if (err) *err = nil;
        return wa_buildCountryDB();
    }
    return r;
}

static IMP orig_dictInitURLErr = NULL;
static NSDictionary *wa_dictInitURLErr(id self, SEL _cmd, NSURL *url, NSError **err) {
    id r = ((id (*)(id, SEL, NSURL *, NSError **))orig_dictInitURLErr)(self, _cmd, url, err);
    if (!r && wa_isCountryPath(url.path)) {
        os_log_info(wa_log(), "initWithContentsOfURL:error: COUNTRY-MATCH -> synthesized DB");
        if (err) *err = nil;
        return wa_buildCountryDB();
    }
    return r;
}

static IMP orig_arrURLErr = NULL;
static NSArray *wa_arrURLErr(id self, SEL _cmd, NSURL *url, NSError **err) {
    id r = ((id (*)(id, SEL, NSURL *, NSError **))orig_arrURLErr)(self, _cmd, url, err);
    if (!r && wa_isCountryPath(url.path)) {
        os_log_info(wa_log(), "arrayWithContentsOfURL:error: COUNTRY-MATCH -> DB keys");
        if (err) *err = nil;
        return wa_buildCountryDB().allKeys;
    }
    return r;
}

static IMP orig_arrInitURLErr = NULL;
static NSArray *wa_arrInitURLErr(id self, SEL _cmd, NSURL *url, NSError **err) {
    id r = ((id (*)(id, SEL, NSURL *, NSError **))orig_arrInitURLErr)(self, _cmd, url, err);
    if (!r && wa_isCountryPath(url.path)) {
        os_log_info(wa_log(), "initWithContentsOfURL:error:(NSArray) COUNTRY-MATCH -> DB keys");
        if (err) *err = nil;
        return wa_buildCountryDB().allKeys;
    }
    return r;
}

// +[NSDictionary dictionaryWithContentsOfFile:]
static IMP orig_dictFile = NULL;
static id wa_dictFile(id self, SEL _cmd, NSString *path) {
    id r = ((id (*)(id, SEL, NSString *))orig_dictFile)(self, _cmd, path);
    if (!r && wa_isCountryPath(path)) {
        os_log_info(wa_log(), "dictionaryWithContentsOfFile MISS for %{public}@ -> synthesizing", path);
        return wa_buildCountryDB();
    }
    return r;
}

// +[NSDictionary dictionaryWithContentsOfURL:]
static IMP orig_dictURL = NULL;
static id wa_dictURL(id self, SEL _cmd, NSURL *url) {
    id r = ((id (*)(id, SEL, NSURL *))orig_dictURL)(self, _cmd, url);
    if (!r && wa_isCountryPath(url.path)) {
        os_log_info(wa_log(), "dictionaryWithContentsOfURL MISS for %{public}@ -> synthesizing", url.path);
        return wa_buildCountryDB();
    }
    return r;
}

// -[NSDictionary initWithContentsOfFile:]
static IMP orig_dictInitFile = NULL;
static id wa_dictInitFile(id self, SEL _cmd, NSString *path) {
    id r = ((id (*)(id, SEL, NSString *))orig_dictInitFile)(self, _cmd, path);
    if (!r && wa_isCountryPath(path)) {
        os_log_info(wa_log(), "initWithContentsOfFile MISS for %{public}@ -> synthesizing", path);
        return wa_buildCountryDB();
    }
    return r;
}

// -[NSDictionary initWithContentsOfURL:]
static IMP orig_dictInitURL = NULL;
static id wa_dictInitURL(id self, SEL _cmd, NSURL *url) {
    id r = ((id (*)(id, SEL, NSURL *))orig_dictInitURL)(self, _cmd, url);
    if (!r && wa_isCountryPath(url.path)) {
        os_log_info(wa_log(), "initWithContentsOfURL MISS for %{public}@ -> synthesizing", url.path);
        return wa_buildCountryDB();
    }
    return r;
}

// -[NSArray initWithContentsOfFile:]
static IMP orig_arrInitFile = NULL;
static id wa_arrInitFile(id self, SEL _cmd, NSString *path) {
    id r = ((id (*)(id, SEL, NSString *))orig_arrInitFile)(self, _cmd, path);
    if (!r && wa_isCountryPath(path)) {
        os_log_info(wa_log(), "NSArray initWithContentsOfFile MISS for %{public}@ -> synthesizing", path);
        return wa_buildCountryDB().allKeys;
    }
    return r;
}

// -[NSArray initWithContentsOfURL:]
static IMP orig_arrInitURL = NULL;
static id wa_arrInitURL(id self, SEL _cmd, NSURL *url) {
    id r = ((id (*)(id, SEL, NSURL *))orig_arrInitURL)(self, _cmd, url);
    if (!r && wa_isCountryPath(url.path)) {
        os_log_info(wa_log(), "NSArray initWithContentsOfURL MISS for %{public}@ -> synthesizing", url.path);
        return wa_buildCountryDB().allKeys;
    }
    return r;
}

static void wa_swizzle(Class cls, SEL sel, IMP imp, IMP *origOut) {
    Method m = class_getClassMethod(cls, sel);
    if (!m) {
        os_log_fault(wa_log(), "SWIZZLE FAIL: %s +%s not found", class_getName(cls), sel_getName(sel));
        return;
    }
    if (origOut) *origOut = method_getImplementation(m);
    method_setImplementation(m, imp);
    os_log_info(wa_log(), "swizzled +[%s %s]", class_getName(cls), sel_getName(sel));
}

static void wa_swizzle_inst(Class cls, SEL sel, IMP imp, IMP *origOut) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        os_log_fault(wa_log(), "SWIZZLE-INST FAIL: %s -%s not found", class_getName(cls), sel_getName(sel));
        return;
    }
    if (origOut) *origOut = method_getImplementation(m);
    method_setImplementation(m, imp);
    os_log_info(wa_log(), "swizzled -[%s %s]", class_getName(cls), sel_getName(sel));
}

__attribute__((constructor))
static void wa_init(void) {
    os_log_info(wa_log(), "waContainerFix v14 constructor running");
    wa_marker(@"=== waContainerFix v14 constructor ===");

    // v10/v11: anti-tamper evasion — init dyld interpose reals FIRST so the
    // fakes are correct before any swizzle/launch activity
    wa_antiDetectInit();
    wa_marker(@"antiDetect init done");

    // v6/v7: universal missing-selector synthesis (kills the whole crash family)
    wa_swizzle([NSObject class], @selector(resolveInstanceMethod:),
               (IMP)wa_resolveInstance, NULL);
    wa_marker(@"swizzled resolveInstanceMethod:");
    wa_swizzle([NSObject class], @selector(resolveClassMethod:),
               (IMP)wa_resolveClass, NULL);
    wa_marker(@"swizzled resolveClassMethod:");

    // v2: NSURL nil guards
    wa_swizzle([NSURL class], @selector(fileURLWithPath:),
               (IMP)wa_fileURLWithPath, &orig_fileURLWithPath);
    wa_swizzle([NSURL class], @selector(fileURLWithPath:isDirectory:),
               (IMP)wa_fileURLWithPathIsDir, &orig_fileURLWithPathIsDir);

    // v2: fake app-group container -> home
    wa_swizzle_inst([NSFileManager class], @selector(containerURLForSecurityApplicationGroupIdentifier:),
                    (IMP)wa_containerURL, &orig_containerURL);

    // v5: fileExistsAtPath discovery
    wa_swizzle_inst([NSFileManager class], @selector(fileExistsAtPath:),
                    (IMP)wa_fileExists, &orig_fileExists);
    wa_swizzle_inst([NSFileManager class], @selector(fileExistsAtPath:isDirectory:),
                    (IMP)wa_fileExistsIsDir, &orig_fileExistsIsDir);

    // v5: NSString readers
    wa_swizzle([NSString class], @selector(stringWithContentsOfFile:encoding:error:),
               (IMP)wa_strFile, &orig_strFile);
    wa_swizzle_inst([NSString class], @selector(initWithContentsOfFile:encoding:error:),
                    (IMP)wa_strInitFile, &orig_strInitFile);

    // v5: NSData readers
    wa_swizzle([NSData class], @selector(dataWithContentsOfFile:),
               (IMP)wa_dataFile, &orig_dataFile);
    wa_swizzle([NSData class], @selector(dataWithContentsOfURL:),
               (IMP)wa_dataURL, &orig_dataURL);
    wa_swizzle_inst([NSData class], @selector(initWithContentsOfFile:),
                    (IMP)wa_dataInitFile, &orig_dataInitFile);

    // v5: error:-variant dict/array readers
    wa_swizzle([NSDictionary class], @selector(dictionaryWithContentsOfURL:error:),
               (IMP)wa_dictURLErr, &orig_dictURLErr);
    wa_swizzle_inst([NSDictionary class], @selector(initWithContentsOfURL:error:),
                    (IMP)wa_dictInitURLErr, &orig_dictInitURLErr);
    wa_swizzle([NSArray class], @selector(arrayWithContentsOfURL:error:),
               (IMP)wa_arrURLErr, &orig_arrURLErr);
    wa_swizzle_inst([NSArray class], @selector(initWithContentsOfURL:error:),
                    (IMP)wa_arrInitURLErr, &orig_arrInitURLErr);

    // v3/v4: country DB synthesis on read-failure
    wa_swizzle([NSDictionary class], @selector(dictionaryWithContentsOfFile:),
               (IMP)wa_dictFile, &orig_dictFile);
    wa_swizzle([NSDictionary class], @selector(dictionaryWithContentsOfURL:),
               (IMP)wa_dictURL, &orig_dictURL);
    wa_swizzle_inst([NSDictionary class], @selector(initWithContentsOfFile:),
                    (IMP)wa_dictInitFile, &orig_dictInitFile);
    wa_swizzle_inst([NSDictionary class], @selector(initWithContentsOfURL:),
                    (IMP)wa_dictInitURL, &orig_dictInitURL);
    wa_swizzle_inst([NSArray class], @selector(initWithContentsOfFile:),
                    (IMP)wa_arrInitFile, &orig_arrInitFile);
    wa_swizzle_inst([NSArray class], @selector(initWithContentsOfURL:),
                    (IMP)wa_arrInitURL, &orig_arrInitURL);
}
