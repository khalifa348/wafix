// waContainerFix v3 — nil-guard NSURL (v2) + synthesize the country DB
// Evidence chain:
//  ME28 .ips 214048: Thread 0 abort at WhatsApp+0x100150c = +[NSURL fileURLWithPath:] with nil
//    (inside SharedModules super-init path) — v1 container swizzle was the wrong target.
//  ME29 logs: v2 nil-guards FIRED (22:16:29.079 "fileURLWithPath:nil GUARDED -> home" x2)
//    -> super-init survives -> app runs +2s -> THEN:
//    "-[__NSCFConstantString enumerateKeysAndObjectsUsingBlock:]: unrecognized selector"
//    = country-DB global still holds a compile-time placeholder STRING because the real
//    DB load (file read) never succeeded in the fake container.
//  v3: keep the guards, ADD dictionaryWithContentsOfFile:/URL: hook that fabricates a
//    real country dictionary from the bundle's countries.tsv when the original read
//    fails on a "country-ish" path.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static os_log_t wa_log(void) {
    static os_log_t l;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        l = os_log_create("com.wafix", "dylib");
    });
    return l;
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

// Build a real NSDictionary out of countries.tsv. Format per line:
//   ISO \t CC \t ITU \t LEN \t MNP \t FORMATS \t REPL \t AREA \t DIALLEN \t REGION
// We keep keys = ISO codes (like the real DB) with a small value dict.
static NSDictionary *wa_buildCountryDB(void) {
    NSString *tsvPath = [[NSBundle mainBundle] pathForResource:@"countries"
                                                        ofType:@"tsv"
                                                   inDirectory:@"Frameworks/SharedModules.framework"];
    if (!tsvPath) {
        // fall back to scanning the framework dir
        NSString *fw = [[[NSBundle mainBundle] bundlePath]
            stringByAppendingPathComponent:@"Frameworks/SharedModules.framework"];
        tsvPath = [fw stringByAppendingPathComponent:@"countries.tsv"];
    }
    NSError *err = nil;
    NSString *txt = [NSString stringWithContentsOfFile:tsvPath encoding:NSUTF8StringEncoding error:&err];
    if (!txt) {
        os_log_fault(wa_log(), "countries.tsv unreadable: %{public}@", err.localizedDescription);
        return nil;
    }
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    for (NSString *line in [txt componentsSeparatedByString:@"\n"]) {
        NSArray *f = [line componentsSeparatedByString:@"\t"];
        if (f.count < 3) continue;
        NSString *iso = f[0];
        if (iso.length != 2) continue;
        out[iso] = @{
            @"cc": f[1],                 // country/ITU code as string
            @"itu": f[2],
            @"iso": iso,
        };
    }
    os_log_info(wa_log(), "synthesized country DB: %lu entries", (unsigned long)out.count);
    return out;
}

// +[NSDictionary dictionaryWithContentsOfFile:]
static IMP orig_dictFile = NULL;
static id wa_dictFile(id self, SEL _cmd, NSString *path) {
    id r = ((id (*)(id, SEL, NSString *))orig_dictFile)(self, _cmd, path);
    if (!r && path) {
        NSString *low = path.lowercaseString;
        if ([low containsString:@"countr"] || [low containsString:@"country"]) {
            os_log_info(wa_log(), "dictionaryWithContentsOfFile MISS for %{public}@ -> synthesizing", path);
            if (!g_fakeCountryDB) g_fakeCountryDB = wa_buildCountryDB();
            if (g_fakeCountryDB) return g_fakeCountryDB;
        }
    }
    return r;
}

// +[NSDictionary dictionaryWithContentsOfURL:]
static IMP orig_dictURL = NULL;
static id wa_dictURL(id self, SEL _cmd, NSURL *url) {
    id r = ((id (*)(id, SEL, NSURL *))orig_dictURL)(self, _cmd, url);
    if (!r && url) {
        NSString *low = url.path.lowercaseString;
        if ([low containsString:@"countr"] || [low containsString:@"country"]) {
            os_log_info(wa_log(), "dictionaryWithContentsOfURL MISS for %{public}@ -> synthesizing", url.path);
            if (!g_fakeCountryDB) g_fakeCountryDB = wa_buildCountryDB();
            if (g_fakeCountryDB) return g_fakeCountryDB;
        }
    }
    return r;
}

// -[NSDictionary initWithContentsOfFile:]
static IMP orig_dictInitFile = NULL;
static id wa_dictInitFile(id self, SEL _cmd, NSString *path) {
    id r = ((id (*)(id, SEL, NSString *))orig_dictInitFile)(self, _cmd, path);
    if (!r && path) {
        NSString *low = path.lowercaseString;
        if ([low containsString:@"countr"] || [low containsString:@"country"]) {
            os_log_info(wa_log(), "initWithContentsOfFile MISS for %{public}@ -> synthesizing", path);
            if (!g_fakeCountryDB) g_fakeCountryDB = wa_buildCountryDB();
            if (g_fakeCountryDB) return g_fakeCountryDB;
        }
    }
    return r;
}

static void wa_swizzle(Class cls, SEL sel, IMP imp, IMP *origOut) {
    Method m = class_getClassMethod(cls, sel);
    if (!m) {
        os_log_fault(wa_log(), "SWIZZLE FAIL: %s +%s not found", class_getName(cls), sel_getName(sel));
        return;
    }
    *origOut = method_getImplementation(m);
    method_setImplementation(m, imp);
    os_log_info(wa_log(), "swizzled +[%s %s]", class_getName(cls), sel_getName(sel));
}

__attribute__((constructor))
static void wa_init(void) {
    os_log_info(wa_log(), "waContainerFix v3 constructor running");

    // v2: NSURL nil guards
    wa_swizzle([NSURL class], @selector(fileURLWithPath:),
               (IMP)wa_fileURLWithPath, &orig_fileURLWithPath);
    wa_swizzle([NSURL class], @selector(fileURLWithPath:isDirectory:),
               (IMP)wa_fileURLWithPathIsDir, &orig_fileURLWithPathIsDir);

    // v2: fake app-group container -> home
    wa_swizzle([NSFileManager class], @selector(containerURLForSecurityApplicationGroupIdentifier:),
               (IMP)wa_containerURL, &orig_containerURL);

    // v3: country DB synthesis on read-failure
    wa_swizzle([NSDictionary class], @selector(dictionaryWithContentsOfFile:),
               (IMP)wa_dictFile, &orig_dictFile);
    wa_swizzle([NSDictionary class], @selector(dictionaryWithContentsOfURL:),
               (IMP)wa_dictURL, &orig_dictURL);
    wa_swizzle([NSDictionary class], @selector(initWithContentsOfFile:),
               (IMP)wa_dictInitFile, &orig_dictInitFile);
}
