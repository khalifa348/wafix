// waContainerFix v9 — v8 + os_log-encode blacklist + de-duped markers.
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

// return YES if the class does REAL forwarding (NSProxy-like) — don't hijack it
static BOOL wa_hasRealForwarding(Class cls) {
    IMP mine = class_getMethodImplementation([NSObject class], @selector(forwardInvocation:));
    IMP theirs = class_getMethodImplementation(cls, @selector(forwardInvocation:));
    return theirs != mine;
}

static BOOL wa_resolveInstance(id self, SEL _cmd, SEL name) {
    Class cls = (Class)self;
    const char *clsName = class_getName(cls);
    const char *selName = sel_getName(name);
    // v9: os_log private path — stock behavior, instant NO, no log/marker churn
    if (wa_isOsLogSelector(selName)) return NO;
    os_log_info(wa_log(), "RESOLVE-INST %s -%s -> no-op", clsName, selName);
    wa_markerOnce([NSString stringWithFormat:@"RESOLVE-INST %s -%s", clsName, selName]);
    if (wa_hasRealForwarding(cls)) {
        os_log_info(wa_log(), "RESOLVE-INST %s -%s -> forwarding class, hands off", clsName, selName);
        return NO;
    }
    if (class_getInstanceMethod(cls, name)) return YES;   // already added (re-entry guard)
    if (!class_addMethod(cls, name, (IMP)wa_noop, "@@:")) {
        os_log_fault(wa_log(), "RESOLVE-INST ADD FAIL %s -%s", clsName, selName);
        return NO;
    }
    os_log_info(wa_log(), "RESOLVE-INST %s -%s -> no-op ADDED", clsName, selName);
    return YES;
}

static BOOL wa_resolveClass(id self, SEL _cmd, SEL name) {
    Class meta = object_getClass(self);
    const char *clsName = class_getName(meta);
    const char *selName = sel_getName(name);
    // v9: os_log private path — stock behavior, instant NO
    if (wa_isOsLogSelector(selName)) return NO;
    os_log_info(wa_log(), "RESOLVE-CLASS %s +%s -> no-op", clsName, selName);
    wa_markerOnce([NSString stringWithFormat:@"RESOLVE-CLASS %s +%s", clsName, selName]);
    if (wa_hasRealForwarding(meta)) {
        os_log_info(wa_log(), "RESOLVE-CLASS %s +%s -> forwarding class, hands off", clsName, selName);
        return NO;
    }
    if (class_getClassMethod(meta, name)) return YES;      // already added (re-entry guard)
    if (!class_addMethod(meta, name, (IMP)wa_noop, "@@:")) {
        os_log_fault(wa_log(), "RESOLVE-CLASS ADD FAIL %s +%s", clsName, selName);
        return NO;
    }
    os_log_info(wa_log(), "RESOLVE-CLASS %s +%s -> no-op ADDED", clsName, selName);
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
    os_log_info(wa_log(), "waContainerFix v9 constructor running");
    wa_marker(@"=== waContainerFix v9 constructor ===");

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
