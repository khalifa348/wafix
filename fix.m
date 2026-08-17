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
#import <netdb.h>
#import <arpa/inet.h>
#import <netinet/in.h>
#import <fcntl.h>
#import <unistd.h>

// forward decl (wa_marker defined later in file)
static void wa_marker(NSString *line);

// ---------- v10: dyld interpose (anti-tamper evasion) ----------
// v15: no real_* function pointers — the fakes call the imported symbols
// DIRECTLY (dyld resolves the interposer's own imports to the REAL libdyld
// functions; it never self-interposes, so no capture is needed).
static const struct mach_header *g_ourHeader = NULL;
static uint32_t g_ourIndex = UINT32_MAX;
static int g_realsInited = 0;

static void wa_antiDetectInit(void) {
    if (g_realsInited) return;
    // v15: NO dlsym capture AT ALL. v14/v13 lesson: dlsym(RTLD_DEFAULT, ...)
    // for an interposed symbol returns the INTERPOSED REPLACEMENT (our own
    // fake — the captured "reals" were app-region addresses == our dylib!),
    // so calling the captured pointer recursed into ourselves and died
    // before init completed. The CORRECT pattern for an interposer: call
    // the imported symbol DIRECTLY — dyld resolves our own imports to the
    // REAL libdyld functions (it never self-interposes the interposer).
    g_realsInited = 1;
    // our own header via dladdr on our code (direct call = real dladdr)
    Dl_info info;
    if (dladdr((const void *)&wa_antiDetectInit, &info)) {
        g_ourHeader = info.dli_fbase;
    }
    // our index in the real dyld list (direct calls = real functions)
    if (g_ourHeader) {
        uint32_t n = _dyld_image_count();
        for (uint32_t i = 0; i < n; i++) {
            if (_dyld_get_image_header(i) == g_ourHeader) { g_ourIndex = i; break; }
        }
        wa_marker([NSString stringWithFormat:@"antiDetect: ourHeader=%p ourIndex=%u count=%u",
                   g_ourHeader, g_ourIndex, n]);
    } else {
        wa_marker(@"antiDetect: ourHeader=NULL (dladdr failed)");
    }
}

static uint32_t wa_fake_dyld_image_count(void) {
    wa_antiDetectInit();
    uint32_t n = _dyld_image_count();  // direct call = REAL (no self-interpose)
    return (g_ourIndex < n) ? n - 1 : n;
}

static const char *wa_fake_dyld_get_image_name(uint32_t index) {
    wa_antiDetectInit();
    if (g_ourIndex != UINT32_MAX && index >= g_ourIndex) index++;
    return _dyld_get_image_name(index);  // direct call = REAL
}

static const struct mach_header *wa_fake_dyld_get_image_header(uint32_t index) {
    wa_antiDetectInit();
    if (g_ourIndex != UINT32_MAX && index >= g_ourIndex) index++;
    return _dyld_get_image_header(index);  // direct call = REAL
}

// swallow add/remove image callbacks — the anti-tamper never learns of our dylib
// v16: BRIDGE pass-through for add/remove image callbacks. v15 swallowed
// them (deliberately dropped) -> WhatsApp's integrity callback registered at
// startup never fired -> at ~15-20s the tamper concluded dyld was
// compromised -> clean exit(). Now: register ONE bridge with the REAL dyld;
// the bridge forwards every callback to the user's callback EXCEPT when the
// image is OUR dylib (that one call is dropped, so the tamper never learns
// our name, while ALL legitimate dyld callback consumers work normally).
static void (*g_wa_cb_add[8])(const struct mach_header *, intptr_t);
static void (*g_wa_cb_remove[8])(const struct mach_header *, intptr_t);
static int g_wa_cb_add_count = 0;
static int g_wa_cb_remove_count = 0;

static void wa_bridge_add(const struct mach_header *mh, intptr_t slide) {
    if (mh == g_ourHeader) return;  // hide ourselves
    for (int i = 0; i < g_wa_cb_add_count; i++) {
        if (g_wa_cb_add[i]) g_wa_cb_add[i](mh, slide);
    }
}

static void wa_bridge_remove(const struct mach_header *mh, intptr_t slide) {
    if (mh == g_ourHeader) return;  // hide ourselves
    for (int i = 0; i < g_wa_cb_remove_count; i++) {
        if (g_wa_cb_remove[i]) g_wa_cb_remove[i](mh, slide);
    }
}

static void wa_fake_dyld_register_func_for_add_image(void (*func)(const struct mach_header *, intptr_t)) {
    wa_antiDetectInit();
    if (func) {
        if (g_wa_cb_add_count == 0) _dyld_register_func_for_add_image(wa_bridge_add);  // direct = REAL
        if (g_wa_cb_add_count < 8) g_wa_cb_add[g_wa_cb_add_count++] = func;
    }
}

static void wa_fake_dyld_register_func_for_remove_image(void (*func)(const struct mach_header *, intptr_t)) {
    wa_antiDetectInit();
    if (func) {
        if (g_wa_cb_remove_count == 0) _dyld_register_func_for_remove_image(wa_bridge_remove);  // direct = REAL
        if (g_wa_cb_remove_count < 8) g_wa_cb_remove[g_wa_cb_remove_count++] = func;
    }
}

// dladdr: return 0 (not found) when the address belongs to our dylib
static int wa_fake_dladdr(const void *addr, Dl_info *info) {
    wa_antiDetectInit();
    if (!dladdr(addr, info)) return 0;  // direct call = REAL
    if (info && info->dli_fbase == g_ourHeader) return 0;
    return 1;
}

// DYLD_INTERPOSE section (__DATA,__interpose) — same shape as the SDK macro
#define WA_INTERPOSE(replacement, replacee) \
    __attribute__((used)) static struct { const void *replacement; const void *replacee; } \
    _wa_interpose_##replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&replacement, (const void *)(unsigned long)&replacee };

// v17 PROBE: interpose ONLY dladdr + callbacks. NO count/name/header hiding.
// Question: does dladdr-hiding ALONE trip the ~23s fast check? If yes, the
// fast check is dladdr/consistency-based and ALL hiding is impossible via
// interpose (→ merge architecture). If death moves to ~150s, the fast check
// is enumeration-based.
WA_INTERPOSE(wa_fake_dyld_register_func_for_add_image, _dyld_register_func_for_add_image)
WA_INTERPOSE(wa_fake_dyld_register_func_for_remove_image, _dyld_register_func_for_remove_image)
WA_INTERPOSE(wa_fake_dladdr, dladdr)

// ============ v18: Track B endpoint redirect (chat server → PC) ============
// WhatsApp resolves its chat endpoint via getaddrinfo() on *.whatsapp.net /
// *.whatsapp.com hosts. We interpose getaddrinfo: when the host matches the
// chat-host allowlist AND a redirect config file exists, we return the PC
// (fake server) address instead of the real WhatsApp server.
//
// The config file is Documents/wafix_redirect.txt, containing "IP:PORT"
// (e.g. "192.168.110.143:5222"). NO file = NO redirect (pass-through, so
// registration/real use still work). This is the runtime kill-switch:
//   - registration phase: no file → app talks to real WhatsApp
//   - test phase:        drop file → app's chat connection hits our PC
//
// We deliberately do NOT redirect media/telemetry subdomains (static.,
// mmg., crashlogs., flows., graph., scontent.cdn., api.) — only the chat
// host family (.whatsapp.net/.whatsapp.com top-levels that aren't media).
static char g_redirect_ip[64] = {0};
static int  g_redirect_port = 0;
static int  g_redirect_checked = 0;

static void wa_redirect_load(void) {
    if (g_redirect_checked) return;  // read once per process (kill-switch = file presence at launch)
    g_redirect_checked = 1;
    NSString *cfg = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                     stringByAppendingPathComponent:@"wafix_redirect.txt"];
    NSString *s = [NSString stringWithContentsOfFile:cfg encoding:NSUTF8StringEncoding error:NULL];
    if (!s || s.length == 0) return;  // no config → pass-through mode
    s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    NSArray *parts = [s componentsSeparatedByString:@":"];
    if (parts.count >= 2) {
        NSString *ip = [parts[0] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        NSString *portStr = [parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        int port = portStr.intValue;
        if (ip.length > 0 && port > 0 && port < 65536) {
            strncpy(g_redirect_ip, ip.UTF8String, sizeof(g_redirect_ip) - 1);
            g_redirect_port = port;
            wa_marker([NSString stringWithFormat:@"REDIRECT cfg loaded: %s:%d", g_redirect_ip, g_redirect_port]);
        } else {
            wa_marker([NSString stringWithFormat:@"REDIRECT cfg INVALID: %@", s]);
        }
    } else {
        wa_marker([NSString stringWithFormat:@"REDIRECT cfg malformed: %@", s]);
    }
}

static BOOL wa_isChatHost(const char *node) {
    if (!node) return NO;
    size_t len = strlen(node);
    // media/telemetry prefixes we must NOT redirect
    static const char *skipPrefixes[] = {
        "static.", "mmg.", "mmg-fallback.", "crashlogs.", "flows.", "graph.",
        "scontent.cdn.", "api.", "cdn.", "0s.", "www.", NULL
    };
    for (int i = 0; skipPrefixes[i]; i++) {
        size_t pl = strlen(skipPrefixes[i]);
        if (len > pl && strncasecmp(node, skipPrefixes[i], pl) == 0) return NO;
    }
    // must end in .whatsapp.net or .whatsapp.com
    static const char *suffixes[] = {".whatsapp.net", ".whatsapp.com", NULL};
    for (int i = 0; suffixes[i]; i++) {
        size_t sl = strlen(suffixes[i]);
        if (len > sl && strcasecmp(node + len - sl, suffixes[i]) == 0) return YES;
    }
    return NO;
}

static int wa_fake_getaddrinfo(const char *node, const char *service,
                               const struct addrinfo *hints,
                               struct addrinfo **res) {
    wa_redirect_load();
    if (g_redirect_port != 0 && wa_isChatHost(node)) {
        struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
        struct sockaddr_in *sa = calloc(1, sizeof(struct sockaddr_in));
        sa->sin_family = AF_INET;
        sa->sin_port = htons((uint16_t)g_redirect_port);
        inet_pton(AF_INET, g_redirect_ip, &sa->sin_addr);
        ai->ai_family = AF_INET;
        ai->ai_socktype = SOCK_STREAM;
        ai->ai_protocol = IPPROTO_TCP;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr *)sa;
        ai->ai_next = NULL;
        *res = ai;
        wa_marker([NSString stringWithFormat:@"REDIRECT %s → %s:%d", node, g_redirect_ip, g_redirect_port]);
        return 0;
    }
    // passthrough: call the REAL getaddrinfo directly (v15 pattern — dyld
    // resolves our own imports to the real libsystem function)
    return getaddrinfo(node, service, hints, res);
}

WA_INTERPOSE(wa_fake_getaddrinfo, getaddrinfo)

// ---------- v28: NWConnection endpoint redirect (tb3b) ----------
// v18 hook getaddrinfo NEVER FIRES on iOS 26: the app resolves chat hosts
// via Network.framework (nw_endpoint_create_host), whose DNS resolution
// happens daemon-side (mDNSResponder) — libc getaddrinfo is not called at
// all (marker had ZERO "REDIRECT cfg loaded" lines even though that line
// writes on the FIRST getaddrinfo of any kind).
// v28 interposes nw_endpoint_create_host: EVERY NWConnection created from a
// hostname flows through this function. When the redirect file is present
// and the host is a chat host, rewrite to the PC IP:port.
typedef NSObject *nw_endpoint_t;  // opaque OS_OBJECT — pointer-only use

// declare the symbol so WA_INTERPOSE can take its address (dlsym at runtime
// still finds the REAL one via RTLD_NEXT — two-level namespace on iOS means
// an undefined nw_* symbol would not resolve at load time with only
// Foundation linked, hence the dlsym approach)
extern nw_endpoint_t nw_endpoint_create_host(const char *hostname, const char *port);

static nw_endpoint_t (*wa_real_nw_endpoint_create_host)(const char *, const char *);

static nw_endpoint_t wa_fake_nw_endpoint_create_host(const char *hostname, const char *port) {
    if (!wa_real_nw_endpoint_create_host) {
        // RTLD_NEXT from our image finds the real one in Network.framework
        // (the app links it, so it is loaded by the time any NWConnection
        // is created). Avoids adding -framework Network to the CI build.
        wa_real_nw_endpoint_create_host = dlsym(RTLD_NEXT, "nw_endpoint_create_host");
        if (!wa_real_nw_endpoint_create_host) return nil;  // cannot happen in practice
    }
    wa_redirect_load();
    // v29: log EVERY call (passthrough included) so zero-lines is conclusive —
    // v28 only logged redirects and a silent passthrough was indistinguishable
    // from "interpose never fired"
    if (hostname && wa_isChatHost(hostname)) {
        if (g_redirect_port != 0) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%d", g_redirect_port);
            wa_marker([NSString stringWithFormat:@"REDIRECT nw %s:%s → %s:%s",
                       hostname, port ? port : "?", g_redirect_ip, portbuf]);
            return wa_real_nw_endpoint_create_host(g_redirect_ip, portbuf);
        }
        wa_marker([NSString stringWithFormat:@"NW-CHATHOST %s:%s (no cfg → passthrough)",
                   hostname, port ? port : "?"]);
    } else if (hostname) {
        wa_marker([NSString stringWithFormat:@"NW-ENDPOINT %s:%s (non-chat)",
                   hostname, port ? port : "?"]);
    }
    return wa_real_nw_endpoint_create_host(hostname, port);
}
WA_INTERPOSE(wa_fake_nw_endpoint_create_host, nw_endpoint_create_host)

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

// v19: marker path + write moved to pure POSIX inside wa_marker (see below);
// this Foundation helper removed — it was part of the re-entry crash path.

static void wa_marker(NSString *line) {
    // v19 FIX: PURE POSIX marker write. v18 used NSFileHandle/NSFileManager
    // (Foundation) — our interposed _dyld_register_func_for_add_image is
    // called from INSIDE os_log's own init (_os_trace_init_slow); Foundation
    // file I/O there re-enters os_log_create on a held dispatch_once →
    // "BUG IN CLIENT OF LIBDISPATCH: trying to lock recursively" → abort
    // (crash 154235). open/write/close can never re-enter os_log or
    // CoreServicesInternal, so markers are safe at ANY init stage.
    const char *home = getenv("HOME");
    if (!home || !home[0]) return;
    char path[1024];
    snprintf(path, sizeof(path), "%s/Documents/wafix_marker.txt", home);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    const char *s = line.UTF8String;
    if (s) {
        size_t n = strlen(s);
        if (n) write(fd, s, n);
        write(fd, "\n", 1);
    }
    close(fd);
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

// v26: +bundleForClass on WhatsApp classes returns the app bundle (pristine
// behavior). The asset loader WARequires non-nil — nil aborts launch.
static id wa_bundleForClass(id self, SEL _cmd) {
    return [NSBundle mainBundle];
}

// v11: NEVER call class_getInstanceMethod / class_getMethodImplementation
// inside the resolver — those trigger resolveMethod_locked -> our swizzle ->
// infinite recursion (ME40 crash 03:18:59: 6+ alternating frames, stack
// overflow -> KERN_PROTECTION_FAILURE in localtime_r/os_log). Use
// class_copyMethodList (direct read, no resolution) + class_addMethod only.
static _Thread_local BOOL wa_resolvingInst = NO;
static _Thread_local BOOL wa_resolvingCls = NO;

// v20: only synthesize missing selectors for WhatsApp's OWN classes.
// v19 crashed in BaseBoard's BSXPCCoder +initialize (recursive +initialize
// SIGTRAP, crash 161132): the global NSObject resolver ran for system classes
// during UIKit startup — class_addMethod invalidates the method cache, the
// runtime re-enters +initialize on the same thread → trap. System classes
// get stock behavior (return NO) — their selectors are never missing anyway.
static BOOL wa_isWhatsAppClass(Class cls) {
    const char *img = class_getImageName(cls);
    if (!img) return NO;
    return strstr(img, "WhatsApp") != NULL;
}

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

// v25: case-insensitive blocklist! v24's strstr() checks were case-sensitive
// ("ContainedRemoteViewController" vs the actual selector
// "_containedRemoteViewController" — lowercase 'c') so the remote-VC
// selectors STILL got synthesized and the scene-connection abort (165815)
// repeated. strcasestr fixes it.
static BOOL wa_blocklistedSelector(const char *name) {
    if (strncasecmp(name, "nsli", 4) == 0) return YES;      // CoreAutoLayout NSIS protocol
    if (strcasestr(name, "DynamicContext") != NULL) return YES;  // CoreUI evaluation probe
    if (strcasestr(name, "ContainedRemoteViewController") != NULL) return YES; // UIKit remote-VC internals
    if (strcasestr(name, "RemoteSheet") != NULL) return YES;  // UIKit remote-sheet internals
    return NO;
}

static BOOL wa_resolveInstance(id self, SEL _cmd, SEL name) {
    if (wa_resolvingInst) return NO;   // recursion guard (thread-local)
    Class cls = (Class)self;
    const char *clsName = class_getName(cls);
    const char *selName = sel_getName(name);
    // v9: os_log private path — stock behavior, instant NO, no log/marker churn
    if (wa_isOsLogSelector(selName)) return NO;
    // v20: WhatsApp classes only — never synthesize for system classes
    // (BaseBoard BSXPCCoder +initialize recursion trap, crash 161132)
    if (!wa_isWhatsAppClass(cls)) return NO;
    // v23: blocklist check (nsli_* autolayout internals, CoreUI probes)
    if (wa_blocklistedSelector(selName)) return NO;
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
    // v20: WhatsApp classes only (class-method resolution runs on metaclasses;
    // the metaclass image is the same as the class's)
    if (!wa_isWhatsAppClass(meta)) return NO;
    // v23: blocklist check
    if (wa_blocklistedSelector(selName)) return NO;
    // v11: NO os_log here (re-entry vector, see wa_resolveInstance)
    wa_markerOnce([NSString stringWithFormat:@"RESOLVE-CLASS %s +%s", clsName, selName]);
    if (wa_hasRealForwardingDirect(meta)) {
        return NO;
    }
    wa_resolvingCls = YES;
    // v26: +bundleForClass must return a REAL bundle, not nil. The asset
    // loader (__WhatsAppAssetsImageLoaderClass) calls it during launch and
    // WARequire's the result; pristine resolves it to the app bundle. nil
    // → WAHandleFailureInFunction abort at XPluginsGetFuncPtr (crash 010857).
    IMP imp = (strcmp(selName, "bundleForClass") == 0)
                  ? (IMP)wa_bundleForClass : (IMP)wa_noop;
    BOOL added = class_addMethod(meta, name, imp, "@@:");
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

// forward decl: set during swizzle setup (constructor) — wa_realTsv needs it
static IMP orig_strFile = NULL;
static BOOL g_realTsvLoading = NO;

static NSString *wa_realTsv(void) {
    if (g_realTsv) return g_realTsv;
    // v22 FIX: infinite recursion guard + swizzle bypass. v21 crashed
    // (crash 163225, SIGILL stack overflow): wa_strFile intercepted the
    // countries.tsv read inside wa_realTsv -> wa_realTsv -> ... forever,
    // because g_realTsv is only cached AFTER the read completes. The
    // internal read MUST go through the ORIGINAL IMP, never the swizzle.
    if (g_realTsvLoading) return nil;
    g_realTsvLoading = YES;
    NSString *tsvPath = [[NSBundle mainBundle] pathForResource:@"countries"
                                                        ofType:@"tsv"
                                                   inDirectory:@"Frameworks/SharedModules.framework"];
    if (!tsvPath) {
        NSString *fw = [[[NSBundle mainBundle] bundlePath]
            stringByAppendingPathComponent:@"Frameworks/SharedModules.framework"];
        tsvPath = [fw stringByAppendingPathComponent:@"countries.tsv"];
    }
    NSError *err = nil;
    if (orig_strFile) {
        // bypass our own stringWithContentsOfFile swizzle (path contains "countr")
        g_realTsv = ((NSString *(*)(id, SEL, NSString *, NSStringEncoding, NSError **))orig_strFile)
            (nil, @selector(stringWithContentsOfFile:encoding:error:), tsvPath, NSUTF8StringEncoding, &err);
    } else {
        g_realTsv = [NSString stringWithContentsOfFile:tsvPath encoding:NSUTF8StringEncoding error:&err];
    }
    g_realTsvLoading = NO;
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
    os_log_info(wa_log(), "waContainerFix v29 constructor running");
    wa_marker(@"=== waContainerFix v29 constructor ===");

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
