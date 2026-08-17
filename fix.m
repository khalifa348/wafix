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
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <netdb.h>
#import <arpa/inet.h>
#import <netinet/in.h>
#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <fcntl.h>
#import <unistd.h>
#import <sys/stat.h>

// forward decl (wa_marker defined later in file)
static void wa_marker(NSString *line);
static void wa_markerOnce(NSString *line);
static void wa_swizzle_inst(Class cls, SEL sel, IMP imp, IMP *origOut);
static void wa_swizzle_scoped(Class cls, SEL sel, IMP imp, IMP *origOut);

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

// ---------- v30: nw_connection_create + connect() hooks ----------
// WHY v30: v28/v29 interposed nw_endpoint_create_host, but the MAIN BINARY
// imports only 4 nw_* symbols — nw_connection_create, nw_connection_start,
// nw_connection_send, nw_connection_receive (+ _nw_connection_cancel,
// _nw_connection_set_queue) — NOT nw_endpoint_create_host. Zero NW-ENDPOINT
// lines across the v28+v29 marker segments ⇒ the app never calls it
// (endpoints come from a different layer/path). v30 hooks:
//   * nw_connection_create — EVERY NWConnection, host- OR address-based
//   * connect() — the raw BSD socket path (PJSIP pj_sock_* layer)
// nw_connection_create redirects when the endpoint's hostname is a chat host
// and the redirect file is present; connect() logs destinations (diag only).
typedef NSObject *nw_parameters_t;  // opaque OS_OBJECT — pointer-only use

extern nw_endpoint_t nw_connection_create(nw_endpoint_t endpoint, nw_parameters_t parameters);
extern const char *nw_endpoint_get_hostname(nw_endpoint_t endpoint);
extern uint16_t nw_endpoint_get_port(nw_endpoint_t endpoint);

static nw_endpoint_t (*wa_real_nw_connection_create)(nw_endpoint_t, nw_parameters_t);

static nw_endpoint_t wa_fake_nw_connection_create(nw_endpoint_t endpoint, nw_parameters_t parameters) {
    if (!wa_real_nw_connection_create) {
        wa_real_nw_connection_create = dlsym(RTLD_NEXT, "nw_connection_create");
        if (!wa_real_nw_connection_create) return nil;
    }
    // read the endpoint's hostname if it has one (host-based endpoints only;
    // address-based endpoints return NULL)
    const char *host = nw_endpoint_get_hostname ? nw_endpoint_get_hostname(endpoint) : NULL;
    uint16_t eport = nw_endpoint_get_port ? nw_endpoint_get_port(endpoint) : 0;
    wa_redirect_load();
    if (host && wa_isChatHost(host)) {
        if (g_redirect_port != 0) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%d", g_redirect_port);
            wa_marker([NSString stringWithFormat:@"REDIRECT conn %s:%u → %s:%s",
                       host, eport, g_redirect_ip, portbuf]);
            // rebuild the endpoint onto the PC IP:port, keep parameters
            nw_endpoint_t ne = nw_endpoint_create_host(g_redirect_ip, portbuf);
            if (ne) return wa_real_nw_connection_create(ne, parameters);
        }
        wa_marker([NSString stringWithFormat:@"NW-CONN chathost %s:%u (no cfg → passthrough)",
                   host, eport]);
    } else if (host) {
        wa_marker([NSString stringWithFormat:@"NW-CONN %s:%u (non-chat)", host, eport]);
    } else {
        wa_marker(@"NW-CONN (address-based endpoint)");
    }
    return wa_real_nw_connection_create(endpoint, parameters);
}
WA_INTERPOSE(wa_fake_nw_connection_create, nw_connection_create)

// connect() — raw BSD socket path (PJSIP socket layer). Diagnostic: log
// every outbound TCP connect destination so we can see whether the chat
// socket goes through raw sockets instead of Network.framework.
static int (*wa_real_connect)(int, const struct sockaddr *, socklen_t);

// dedupe: keep at most N unique (ip:port) destinations logged
#define WA_CONNECT_LOG_MAX 40
static char g_connect_seen[WA_CONNECT_LOG_MAX][48];
static int g_connect_seen_n = 0;

static int wa_fake_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    if (!wa_real_connect) {
        wa_real_connect = dlsym(RTLD_NEXT, "connect");
        if (!wa_real_connect) return connect(fd, addr, len);
    }
    if (addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        char ipbuf[INET6_ADDRSTRLEN] = {0};
        int port = 0;
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
            port = ntohs(sin->sin_port);
        } else {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &sin6->sin6_addr, ipbuf, sizeof(ipbuf));
            port = ntohs(sin6->sin6_port);
        }
        if (port != 0 && ipbuf[0]) {
            char line[64];
            snprintf(line, sizeof(line), "%s:%d", ipbuf, port);
            int seen = 0;
            for (int i = 0; i < g_connect_seen_n; i++) {
                if (strcmp(g_connect_seen[i], line) == 0) { seen = 1; break; }
            }
            if (!seen && g_connect_seen_n < WA_CONNECT_LOG_MAX) {
                strncpy(g_connect_seen[g_connect_seen_n], line, sizeof(g_connect_seen[g_connect_seen_n]) - 1);
                g_connect_seen_n++;
                wa_marker([NSString stringWithFormat:@"CONNECT %s", line]);
            }
        }
    }
    return wa_real_connect(fd, addr, len);
}
WA_INTERPOSE(wa_fake_connect, connect)

// ---------- v31: in-app UI driver (registration drive) ----------
// The app is network-idle at the welcome screen — no connection exists to
// redirect until registration advances. dvt accessibility needs root
// tunneld (blocked), screenshots render black (failret), so drive the UI
// from INSIDE the process via a command file:
//   Documents/wafix_drive.txt, one command per line, read once at +8s:
//     DUMP            → log view hierarchy (class, frame, text, label)
//     TYPE <digits>   → focus first UITextField + insertText (real typing)
//     TAP <classpart> → sendActionsForControlEvents:TouchUpInside on the
//                       first UIControl whose class name contains classpart
//   No file / empty → no UI action; app behaves normally.
// All UIKit access via performSelector/NSInvocation — the CI build links
// only Foundation+Network, so no compile-time UIKit symbols.

static void wa_drive_log_view(id view, int depth) {
    if (!view || depth > 10) return;
    @autoreleasepool {
        NSString *cls = NSStringFromClass(object_getClass(view));
        // frame via NSInvocation (struct return)
        CGRect fr = {0};  // no CGRectZero — CI links Foundation+Network only
        SEL frameSel = NSSelectorFromString(@"frame");
        if ([view respondsToSelector:frameSel]) {
            NSMethodSignature *sig = [view methodSignatureForSelector:frameSel];
            if (sig) {
                NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
                inv.target = view;
                inv.selector = frameSel;
                [inv invoke];
                [inv getReturnValue:&fr];
            }
        }
        NSString *extra = @"";
        if ([view isKindOfClass:NSClassFromString(@"UITextField")]) {
            id txt = [view performSelector:NSSelectorFromString(@"text")];
            if (txt) extra = [NSString stringWithFormat:@" text=\"%@\"", txt];
        }
        id al = [view respondsToSelector:NSSelectorFromString(@"accessibilityLabel")]
                ? [view performSelector:NSSelectorFromString(@"accessibilityLabel")] : nil;
        if (al) extra = [extra stringByAppendingFormat:@" label=\"%@\"", al];
        wa_marker([NSString stringWithFormat:@"UI %*s%@ f=%.0f,%.0f %.0fx%.0f%@",
                   depth * 2, "", cls, fr.origin.x, fr.origin.y, fr.size.width, fr.size.height, extra]);
        id subs = [view respondsToSelector:NSSelectorFromString(@"subviews")]
                  ? [view performSelector:NSSelectorFromString(@"subviews")] : nil;
        for (id sv in subs) wa_drive_log_view(sv, depth + 1);
    }
}

static void wa_drive_run(void) {
    NSString *cfg = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
                     stringByAppendingPathComponent:@"wafix_drive.txt"];
    NSString *s = [NSString stringWithContentsOfFile:cfg encoding:NSUTF8StringEncoding error:NULL];
    if (!s) return;
    NSArray *lines = [s componentsSeparatedByString:@"\n"];
    wa_marker([NSString stringWithFormat:@"DRIVE cfg: %@", s]);
    id app = [(id)NSClassFromString(@"UIApplication") performSelector:NSSelectorFromString(@"sharedApplication")];
    if (!app) { wa_marker(@"DRIVE no UIApplication"); return; }
    id windows = [app respondsToSelector:NSSelectorFromString(@"windows")]
                 ? [app performSelector:NSSelectorFromString(@"windows")] : nil;
    if (!windows) { wa_marker(@"DRIVE no windows"); return; }
    NSArray *cmds = [lines filteredArrayUsingPredicate:
                     [NSPredicate predicateWithFormat:@"length > 0"]];
    for (NSString *cmd in cmds) {
        NSString *trimmed = [cmd stringByTrimmingCharactersInSet:
                             [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if ([trimmed hasPrefix:@"DUMP"]) {
            // v46: dump gate-class method lists once (find the recovery API)
            static int wa_dumped_gates = 0;
            if (!wa_dumped_gates) {
                wa_dumped_gates = 1;
                const char *gateCls[] = {
                    "WAChatListLowStorageRecoveryHandler",
                    "WALowStorageAlerts",
                    "WACriticallyLowStorageViewController",
                    "WALowStorageBannerManager",
                    "WAStorageWarningViewController",
                    "FBStorageKitMonitor",
                    "FBWrappedStorageKitConfig",
                };
                for (int gi = 0; gi < 7; gi++) {
                    Class g = NSClassFromString([NSString stringWithUTF8String:gateCls[gi]]);
                    if (!g) { wa_marker([NSString stringWithFormat:@"GATE %s (absent)", gateCls[gi]]); continue; }
                    wa_marker([NSString stringWithFormat:@"GATE %s:", gateCls[gi]]);
                    unsigned int mc = 0;
                    Method *mets = class_copyMethodList(g, &mc);
                    for (unsigned int mj = 0; mj < mc && mj < 40; mj++) {
                        wa_marker([NSString stringWithFormat:@"  GATE  -%s", sel_getName(method_getName(mets[mj]))]);
                    }
                    if (mets) free(mets);
                    // v47: class methods too (WALowStorageAlerts API is class-level)
                    Class meta = object_getClass(g);
                    unsigned int mcc = 0;
                    Method *cms = class_copyMethodList(meta, &mcc);
                    for (unsigned int mj = 0; mj < mcc && mj < 40; mj++) {
                        wa_marker([NSString stringWithFormat:@"  GATE+ +%s", sel_getName(method_getName(cms[mj]))]);
                    }
                    if (cms) free(cms);
                }
            }
            // v40: log root class + presented chain per window (diagnosis)
            for (id w in windows) {
                id root = [w performSelector:NSSelectorFromString(@"rootViewController")];
                if (root) {
                    NSMutableString *chain = [NSMutableString stringWithString:
                        NSStringFromClass(object_getClass(root))];
                    id presented = [root performSelector:@selector(presentedViewController)];
                    while (presented) {
                        [chain appendFormat:@" -> %@", NSStringFromClass(object_getClass(presented))];
                        id next = [presented performSelector:@selector(presentedViewController)];
                        if (next == presented) break;
                        presented = next;
                    }
                    wa_marker([NSString stringWithFormat:@"UI ROOTCHAIN %@", chain]);
                } else {
                    wa_marker(@"UI ROOTCHAIN (nil root)");
                }
            }
            for (id w in windows) wa_drive_log_view(w, 0);
        } else if ([trimmed hasPrefix:@"TYPE "]) {
            NSString *digits = [trimmed substringFromIndex:5];
            // find the first visible UITextField in any window
            id field = nil;
            for (id w in windows) {
                // walk subviews recursively looking for UITextField
                __block id found = nil;
                void (^walk)(id) = ^(id v) {
                    if (found) return;
                    if ([v isKindOfClass:NSClassFromString(@"UITextField")]) { found = v; return; }
                    id subs = [v respondsToSelector:NSSelectorFromString(@"subviews")]
                              ? [v performSelector:NSSelectorFromString(@"subviews")] : nil;
                    for (id sv in subs) walk(sv);
                };
                walk(w);
                if (found) { field = found; break; }
            }
            if (field) {
                [field performSelector:NSSelectorFromString(@"becomeFirstResponder")];
                wa_marker([NSString stringWithFormat:@"DRIVE typing %@ into %@",
                           digits, NSStringFromClass(object_getClass(field))]);
                // insertText: goes through the real UITextInput pipeline
                [field performSelector:NSSelectorFromString(@"insertText:") withObject:digits];
                id txt = [field performSelector:NSSelectorFromString(@"text")];
                wa_marker([NSString stringWithFormat:@"DRIVE field now: %@", txt]);
            } else {
                wa_marker(@"DRIVE no UITextField found");
            }
        } else if ([trimmed hasPrefix:@"TAP "]) {
            NSString *part = [trimmed substringFromIndex:4];
            id ctrl = nil;
            for (id w in windows) {
                __block id found = nil;
                void (^walk)(id) = ^(id v) {
                    if (found) return;
                    NSString *cn = NSStringFromClass(object_getClass(v));
                    if ([cn rangeOfString:part].location != NSNotFound &&
                        [v respondsToSelector:NSSelectorFromString(@"sendActionsForControlEvents:")]) {
                        found = v; return;
                    }
                    id subs = [v respondsToSelector:NSSelectorFromString(@"subviews")]
                              ? [v performSelector:NSSelectorFromString(@"subviews")] : nil;
                    for (id sv in subs) walk(sv);
                };
                walk(w);
                if (found) { ctrl = found; break; }
            }
            if (ctrl) {
                wa_marker([NSString stringWithFormat:@"DRIVE tapping %@ (%@)",
                           NSStringFromClass(object_getClass(ctrl)), part]);
                // UIControlEventTouchUpInside == 1 << 6 — performSelector can't
                // take integers, so call through objc_msgSend instead
                ((void (*)(id, SEL, unsigned long))objc_msgSend)(
                    ctrl, NSSelectorFromString(@"sendActionsForControlEvents:"), 1UL << 6);
            } else {
                wa_marker([NSString stringWithFormat:@"DRIVE no control matching %@", part]);
            }
        } else if ([trimmed hasPrefix:@"STATS"]) {
            // v32: log device storage stats from inside the app
            NSFileManager *fm = [NSFileManager defaultManager];
            NSDictionary *attrs = [fm attributesOfFileSystemForPath:NSHomeDirectory()
                                                              error:nil];
            long long freeBytes = [attrs[NSFileSystemFreeSize] longLongValue];
            long long totalBytes = [attrs[NSFileSystemSize] longLongValue];
            wa_marker([NSString stringWithFormat:@"STATS free=%.1fMB total=%.1fMB",
                       freeBytes / 1048576.0, totalBytes / 1048576.0]);
        } else {
            wa_marker([NSString stringWithFormat:@"DRIVE unknown cmd: %@", trimmed]);
        }
    }
}

// ---------- v32: low-storage gate bypass ----------
// WhatsApp blocks at a "Storage is full" screen when the device is low on
// space, before any UI/network work. Neutralize the gate so the app reaches
// the welcome screen. The gate selectors (from binary string scan):
//   -presentLowStorageModalIfNeededFromParent:
//   -showLowStorageModalIfNeeded
//   -shouldHandleLowStorage
//   -criticallyLowStorageDidOccur:
static void wa_noop_void_id(id self, SEL _cmd, id arg) { (void)self; (void)_cmd; (void)arg; }
static void wa_noop_void(id self, SEL _cmd) { (void)self; (void)_cmd; }
static BOOL wa_noop_false(id self, SEL _cmd) { (void)self; (void)_cmd; return NO; }

static void wa_bypass_low_storage(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *classes = (Class *)malloc(sizeof(Class) * n);
    n = objc_getClassList(classes, n);
    const char *selNames[] = {
        "presentLowStorageModalIfNeededFromParent:",
        "showLowStorageModalIfNeeded",
        "criticallyLowStorageDidOccur:",
    };
    SEL sels[3];
    sels[0] = sel_registerName(selNames[0]);
    sels[1] = sel_registerName(selNames[1]);
    sels[2] = sel_registerName(selNames[2]);
    // shouldHandleLowStorage returns BOOL (must exist before the loop; v34)
    SEL sh = sel_registerName("shouldHandleLowStorage");
    int patched = 0;
    int skipped_system = 0;
    for (int i = 0; i < n; i++) {
        Class cls = classes[i];
        if (class_isMetaClass(cls)) continue;
        // v33 FIX: ONLY patch classes from the main WhatsApp executable.
        // v32 patched EVERY class with these selectors — including Apple
        // system frameworks (CloudKit CK*: CKScopedResponder, CKTreeNode…),
        // which crashed the app ~1s after launch (marker died mid-scan on
        // CKScopedResponder). class_getImageName tells us which image a
        // class came from; system classes are never touched now.
        const char *img = class_getImageName(cls);
        if (!img || !strstr(img, "WhatsApp.app/WhatsApp")) {
            skipped_system++;
            continue;
        }
        // v34 FIX: use class_copyMethodList (DIRECT read, no resolution
        // trigger) instead of class_getInstanceMethod. v33's
        // class_getInstanceMethod calls triggered the resolveInstanceMethod:
        // swizzle for EVERY class missing the selector → 500K+ marker writes
        // on the main thread → black UI for minutes. Direct list read cannot
        // re-enter the resolver.
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(cls, &mcount);
        if (!methods) continue;
        for (unsigned int mi = 0; mi < mcount; mi++) {
            SEL name = method_getName(methods[mi]);
            if (name == sels[0] || name == sels[1] || name == sels[2]) {
                IMP cur = method_getImplementation(methods[mi]);
                if (cur != (IMP)wa_noop_void && cur != (IMP)wa_noop_void_id) {
                    IMP imp = (name == sels[2]) ? (IMP)wa_noop_void_id : (IMP)wa_noop_void;
                    method_setImplementation(methods[mi], imp);
                    wa_markerOnce([NSString stringWithFormat:@"BYPASS patched %s on %s",
                                   sel_getName(name), class_getName(cls)]);
                    patched++;
                }
            } else if (name == sh) {
                IMP cur = method_getImplementation(methods[mi]);
                if (cur != (IMP)wa_noop_false) {
                    method_setImplementation(methods[mi], (IMP)wa_noop_false);
                    wa_markerOnce([NSString stringWithFormat:@"BYPASS patched shouldHandleLowStorage on %s",
                                   class_getName(cls)]);
                    patched++;
                }
            }
        }
        free(methods);
    }
    free(classes);
    wa_marker([NSString stringWithFormat:@"BYPASS scan done (%d patches, %d system skipped)", patched, skipped_system]);
}

// Dismiss any presented low-storage / storage-warning modal so the app
// proceeds even if the gate fired before we patched it.
static void wa_dismiss_storage_modal(void) {
    id app = [(id)NSClassFromString(@"UIApplication") performSelector:@selector(sharedApplication)];
    if (!app) return;
    id windows = [app performSelector:@selector(windows)];
    for (id w in windows) {
        id root = [w performSelector:@selector(rootViewController)];
        id vc = root;
        id presented = [vc performSelector:@selector(presentedViewController)];
        while (presented) {
            NSString *cn = NSStringFromClass(object_getClass(presented));
            if ([cn containsString:@"LowStorage"] || [cn containsString:@"StorageWarning"]) {
                wa_marker([NSString stringWithFormat:@"BYPASS dismissing %@", cn]);
                [presented performSelector:@selector(dismissViewControllerAnimated:completion:)
                                withObject:@NO withObject:nil];
            }
            vc = presented;
            presented = [vc performSelector:@selector(presentedViewController)];
        }
    }
}

// ---------- v35: kill the low-storage screen at the SOURCE ----------
// v34 proved the app RE-PRESENTS the storage modal after one-shot
// dismissals (sticky _WACriticallyLowSpaceDidOccur flag + a third
// presentation path we haven't hooked). Robust fix: swizzle
// viewDidAppear: on both storage VCs so the screen dismisses itself
// the instant it appears — no matter how many times it's re-presented —
// plus a repeating dismissal timer as backup.

static IMP wa_orig_storage_vc1_viewDidAppear = NULL;
static IMP wa_orig_storage_vc2_viewDidAppear = NULL;

static void wa_storage_vc_kill_on_appear(id self, SEL _cmd, BOOL animated) {
    // v36: call THIS class's own original (v35 called VC1's original for
    // both — harmless in practice but wrong; keep them separate)
    Class cls = object_getClass(self);
    IMP orig = (cls == NSClassFromString(@"WAStorageWarningViewController"))
                   ? wa_orig_storage_vc2_viewDidAppear
                   : wa_orig_storage_vc1_viewDidAppear;
    if (orig) ((void (*)(id, SEL, BOOL))orig)(self, _cmd, animated);
    wa_marker([NSString stringWithFormat:@"BYPASS killing %@ on appear",
               NSStringFromClass(cls)]);
    // dismiss from the presenting parent (async — avoid recursion)
    dispatch_async(dispatch_get_main_queue(), ^{
        id parent = [self performSelector:@selector(presentingViewController)];
        if (parent) {
            [parent performSelector:@selector(dismissViewControllerAnimated:completion:)
                         withObject:@NO withObject:nil];
        }
    });
}

static void wa_kill_storage_on_appear(void) {
    // v36: use wa_swizzle_scoped (NEVER class_getInstanceMethod+
    // method_setImplementation on an inherited method — that would mutate
    // UIViewController's implementation for every VC in the app).
    Class c1 = NSClassFromString(@"WACriticallyLowStorageViewController");
    Class c2 = NSClassFromString(@"WAStorageWarningViewController");
    if (c1 && !wa_orig_storage_vc1_viewDidAppear) {
        wa_swizzle_scoped(c1, @selector(viewDidAppear:),
                          (IMP)wa_storage_vc_kill_on_appear, &wa_orig_storage_vc1_viewDidAppear);
        wa_marker([NSString stringWithFormat:@"BYPASS viewDidAppear swizzled on %s",
                   class_getName(c1)]);
    }
    if (c2 && !wa_orig_storage_vc2_viewDidAppear) {
        wa_swizzle_scoped(c2, @selector(viewDidAppear:),
                          (IMP)wa_storage_vc_kill_on_appear, &wa_orig_storage_vc2_viewDidAppear);
        wa_marker([NSString stringWithFormat:@"BYPASS viewDidAppear swizzled on %s",
                   class_getName(c2)]);
    }
}

// ---------- v37/v38: block the storage-screen PRESENTATION at the source ----------
// v36 proved the app RE-PRESENTS the storage modal instantly after every
// dismissal (marker shows a dismissal loop while the screen stays up). The
// re-presenter is some path we haven't nopped yet. Instead of chasing it,
// nullify the presentation call itself: any -presentViewController: whose
// incoming VC is a storage VC (directly or nav-wrapped) is swallowed, and we
// log WHO tried to present it so the marker names the source.
//
// v38 FIX: v37 blocked only UIViewController's own implementation, but the
// DUMP showed the modal container still appears with ZERO "BLOCKED" marker
// lines — the presenter goes through a SUBCLASS OVERRIDE of
// presentViewController:/setRootViewController: (WA's own VC classes),
// which bypasses a UIViewController-level swizzle. So v38 patches every
// WhatsApp class that IMPLEMENTS these selectors (per-class originals kept
// so normal presentations still work), plus zeroes the exported global
// _WACriticallyLowSpaceDidOccur flag via dlsym.

static BOOL wa_is_storage_vc(id vc) {
    if (!vc) return NO;
    id target = vc;
    Class navCls = NSClassFromString(@"UINavigationController");
    if (navCls && [target isKindOfClass:navCls]) {
        id top = [target performSelector:@selector(topViewController)];
        if (top) target = top;
    }
    Class c1 = NSClassFromString(@"WACriticallyLowStorageViewController");
    Class c2 = NSClassFromString(@"WAStorageWarningViewController");
    return ((c1 && [target isKindOfClass:c1]) || (c2 && [target isKindOfClass:c2]));
}

// per-class original IMPs for the patched presentation selectors
typedef struct wa_orig_pres { Class cls; SEL sel; IMP imp; struct wa_orig_pres *next; } wa_orig_pres_t;
static wa_orig_pres_t *g_orig_pres = NULL;

static IMP wa_orig_pres_imp(Class cls, SEL sel) {
    for (wa_orig_pres_t *p = g_orig_pres; p; p = p->next)
        if (p->cls == cls && p->sel == sel) return p->imp;
    return NULL;
}

static IMP orig_presentVC = NULL;      // UIViewController's own original (fallback)
static IMP orig_setRootVC = NULL;      // UIWindow's own original (fallback)

static void wa_presentVC_block(id self, SEL _cmd, id vc, BOOL animated, id completion) {
    if (wa_is_storage_vc(vc)) {
        wa_marker([NSString stringWithFormat:@"BYPASS BLOCKED storage-modal present from %s",
                   class_getName(object_getClass(self))]);
        if (completion) ((void (^)(void))completion)();
        return;
    }
    IMP orig = wa_orig_pres_imp(object_getClass(self), _cmd);
    if (!orig) orig = orig_presentVC;
    ((void (*)(id, SEL, id, BOOL, id))orig)(self, _cmd, vc, animated, completion);
}

static void wa_presentModalVC_block(id self, SEL _cmd, id vc, BOOL animated) {
    if (wa_is_storage_vc(vc)) {
        wa_marker([NSString stringWithFormat:@"BYPASS BLOCKED storage-modal presentModal from %s",
                   class_getName(object_getClass(self))]);
        return;
    }
    IMP orig = wa_orig_pres_imp(object_getClass(self), _cmd);
    if (!orig) orig = orig_presentVC;
    ((void (*)(id, SEL, id, BOOL))orig)(self, _cmd, vc, animated);
}

// v39/v40: the storage VC is presented ON the window root (set at launch,
// before our +2s patches) and dismissals silently FAIL (marker: found in
// presented chain every 2s, never leaves, ZERO re-presentation hits on any
// patched selector — the modal is stuck, not re-presented). Fix: replace
// the whole window root with the app's NORMAL root (WARootViewController)
// whenever the presented chain holds a storage VC — wiping the stuck modal.
static id wa_make_good_root(void) {
    Class rvc = NSClassFromString(@"WARootViewController");
    id vc = nil;
    if (rvc) {
        @try { vc = [rvc new]; } @catch (NSException *e) { vc = nil; }
    }
    if (!vc) {
        Class blank = NSClassFromString(@"UIViewController");
        if (blank) vc = [blank new];
    }
    return vc;
}

static void wa_swap_storage_root(void) {
    id appCls = NSClassFromString(@"UIApplication");
    if (!appCls) return;
    id app = [appCls performSelector:@selector(sharedApplication)];
    if (!app) return;
    id wins = [app performSelector:@selector(windows)];
    if (![wins isKindOfClass:[NSArray class]]) return;
    for (id w in (NSArray *)wins) {
        id root = [w performSelector:@selector(rootViewController)];
        if (!root) continue;
        if (wa_is_storage_vc(root)) {
            id good = wa_make_good_root();
            if (good) {
                [w performSelector:@selector(setRootViewController:) withObject:good];
                wa_marker([NSString stringWithFormat:@"BYPASS SWAPPED storage root -> %s",
                           class_getName(object_getClass(good))]);
            }
            continue;
        }
        // v40/v42: storage VC stuck in the presented chain — dismiss is
        // failing because the presenting root's view was never loaded
        // (v41 dump: empty UIDropShadowView; screen black). So: strip the
        // storage VIEW from the window and force-load the root's real view.
        id presented = [root performSelector:@selector(presentedViewController)];
        while (presented) {
            if (wa_is_storage_vc(presented)) {
                id pv = [presented performSelector:@selector(view)];
                if (pv) {
                    [pv performSelector:@selector(removeFromSuperview)];
                    wa_marker([NSString stringWithFormat:
                               @"BYPASS STRIPPED stuck storage view from %s root",
                               class_getName(object_getClass(root))]);
                }
                // force the root's own view to load + attach
                if ([root respondsToSelector:@selector(loadViewIfNeeded)]) {
                    [root performSelector:@selector(loadViewIfNeeded)];
                } else {
                    [root performSelector:@selector(view)];
                }
                id rv = [root performSelector:@selector(view)];
                if (rv) {
                    int n = (int)[(id)[rv performSelector:@selector(subviews)] count];
                    wa_marker([NSString stringWithFormat:
                               @"BYPASS root %s view loaded, %d subviews",
                               class_getName(object_getClass(root)), n]);
                }
                break;
            }
            id next = [presented performSelector:@selector(presentedViewController)];
            if (next == presented) break;
            presented = next;
        }
    }
}

static void wa_presentPrivate_block(id self, SEL _cmd, id vc, id anim, id completion) {
    if (wa_is_storage_vc(vc)) {
        wa_marker([NSString stringWithFormat:@"BYPASS BLOCKED storage-modal private-present from %s",
                   class_getName(object_getClass(self))]);
        return;
    }
    IMP orig = wa_orig_pres_imp(object_getClass(self), _cmd);
    if (!orig) orig = orig_presentVC;
    ((void (*)(id, SEL, id, id, id))orig)(self, _cmd, vc, anim, completion);
}

// v41: WAWindow + coordinator classes OVERRIDE setRootViewController: and
// re-dispatch the selector on self — calling their IMP as "orig" from our
// block recurses into our own patched IMP forever (v40 crash: EXC_BAD_ACCESS
// stack overflow in wa_setRootVC_block). Capture UIWindow's TRUE base IMP
// before any swizzling and always call that instead.
static IMP wa_base_setRootVC = NULL;

static void wa_capture_base_setRootVC(void) {
    if (wa_base_setRootVC) return;
    Class uiwin = NSClassFromString(@"UIWindow");
    if (!uiwin) return;
    Method m = class_getInstanceMethod(uiwin, sel_registerName("setRootViewController:"));
    if (m) wa_base_setRootVC = method_getImplementation(m);
}

static void wa_setRootVC_block(id self, SEL _cmd, id vc) {
    if (wa_is_storage_vc(vc)) {
        wa_marker([NSString stringWithFormat:@"BYPASS BLOCKED storage-modal setRoot from %s",
                   class_getName(object_getClass(self))]);
        // give the window the app's NORMAL root so the state machine moves on
        vc = wa_make_good_root();
        if (!vc) return;
    }
    IMP orig = wa_base_setRootVC;
    if (!orig) orig = orig_setRootVC;
    ((void (*)(id, SEL, id))orig)(self, _cmd, vc);
}

// v45: make EVERY storage-state read return "storage is fine". WhatsApp's
// startup skips building its real UI when it thinks storage is critical;
// the VC-level block (v44) kills the screen but the UI still never builds.
// Patch any instance/class method on WhatsApp classes whose selector name
// contains critically-low-storage markers to a zero-returning stub.
// Deliberately NOT matching bare "storage" (would nuke WAChatStorage DB
// methods). Idempotent: re-entry sees the stub already installed.
// v46: broader net. StorageKit (Meta framework) drives the real state and
// lives OUTSIDE the WhatsApp image — match any image for the strict needles,
// and "storage" only inside WhatsApp images (protects WAChatStorage DB).
// NEVER zero `lowStorageRecoveryHandler` (nil handler kills app's recovery).
static id wa_stub_zero(id self, SEL _cmd) { (void)self; (void)_cmd; return 0; }

static int wa_sel_is_storage_related(const char *sn, int inWhatsApp) {
    char lower[256];
    size_t k = 0;
    for (; sn[k] && k < sizeof(lower) - 1; k++) lower[k] = (sn[k] >= 'A' && sn[k] <= 'Z') ? sn[k] + 32 : sn[k];
    lower[k] = 0;
    const char *strict[] = { "criticallow", "lowspace", "lowstorage", "criticaldisk", "diskstate" };
    for (int m = 0; m < 5; m++) if (strstr(lower, strict[m])) return 1;
    if (inWhatsApp && strstr(lower, "storage")) {
        // protect the recovery HANDLER getter and the DB classes' storage methods
        if (strstr(lower, "recoveryhandler")) return 0;
        if (strstr(lower, "chatstorage")) return 0;
        if (strstr(lower, "databasestorage")) return 0;
        if (strstr(lower, "mediastorage")) return 0;
        return 1;
    }
    return 0;
}

static void wa_neutralize_storage_reads(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *classes = (Class *)malloc(sizeof(Class) * n);
    n = objc_getClassList(classes, n);
    int neutered = 0;
    for (int i = 0; i < n; i++) {
        Class cls = classes[i];
        if (class_isMetaClass(cls)) continue;
        const char *img = class_getImageName(cls);
        int inWhatsApp = img && strstr(img, "WhatsApp.app/WhatsApp");
        // strict needles match ANY image; "storage" needs the WhatsApp image
        // so we don't neuter StorageKit's own plumbing needed by recovery
        if (!inWhatsApp && !(img && (strstr(img, "StorageKit") || strstr(img, "FBSDK") || strstr(img, "Meta")))) continue;
        // instance methods
        unsigned int mc = 0;
        Method *methods = class_copyMethodList(cls, &mc);
        for (unsigned int j = 0; j < mc; j++) {
            SEL sel = method_getName(methods[j]);
            const char *sn = sel_getName(sel);
            if (!sn) continue;
            if (!wa_sel_is_storage_related(sn, inWhatsApp)) continue;
            IMP cur = class_getMethodImplementation(cls, sel);
            if (cur == (IMP)wa_stub_zero) continue;
            method_setImplementation(methods[j], (IMP)wa_stub_zero);
            if (neutered < 30) wa_marker([NSString stringWithFormat:@"NEUTRAL inst %s %s", class_getName(cls), sn]);
            neutered++;
        }
        if (methods) free(methods);
        // class methods
        Class meta = object_getClass(cls);
        unsigned int mcc = 0;
        Method *cms = class_copyMethodList(meta, &mcc);
        for (unsigned int j = 0; j < mcc; j++) {
            SEL sel = method_getName(cms[j]);
            const char *sn = sel_getName(sel);
            if (!sn) continue;
            if (!wa_sel_is_storage_related(sn, inWhatsApp)) continue;
            IMP cur = class_getMethodImplementation(meta, sel);
            if (cur == (IMP)wa_stub_zero) continue;
            method_setImplementation(cms[j], (IMP)wa_stub_zero);
            if (neutered < 30) wa_marker([NSString stringWithFormat:@"NEUTRAL cls %s %s", class_getName(cls), sn]);
            neutered++;
        }
        if (cms) free(cms);
    }
    free(classes);
    wa_marker([NSString stringWithFormat:@"NEUTRAL total %d storage reads zeroed", neutered]);
}

static void wa_block_storage_presentation(void) {
    // v43: this can now fire from objc_addLoadImageFunc (UIKitCore load
    // moment, BEFORE application:didFinishLaunching) — all swizzles below
    // are idempotent (orig_* guards + per-class first-time-only saves)
    // v41: capture UIWindow's TRUE setRootViewController: IMP before any
    // swizzle replaces it — the per-class originals are unsafe (see above)
    wa_capture_base_setRootVC();
    // UIViewController is loaded by the time the app runs, but the dylib
    // itself is Foundation-only — resolve at runtime, never at link time
    Class uivc = NSClassFromString(@"UIViewController");
    if (!uivc) {
        wa_marker(@"BYPASS UIViewController not loaded yet (skip presentation block)");
        return;
    }
    // v37 baseline: UIViewController's own implementation
    if (!orig_presentVC) {
        wa_swizzle_scoped(uivc, @selector(presentViewController:animated:completion:),
                          (IMP)wa_presentVC_block, &orig_presentVC);
        wa_marker(@"BYPASS presentViewController: blocked for storage VCs");
    }
    Class uiw = NSClassFromString(@"UIWindow");
    if (uiw && !orig_setRootVC) {
        wa_swizzle_scoped(uiw, @selector(setRootViewController:),
                          (IMP)wa_setRootVC_block, &orig_setRootVC);
        wa_marker(@"BYPASS setRootViewController: blocked for storage VCs");
    }
    // v38: patch EVERY WhatsApp class that implements these selectors — a
    // subclass override bypasses the UIViewController-level swizzle.
    // v40: also patch UIKit's private presentation funnel
    // _presentViewController:withAnimationController:completion: — public
    // presentViewController: funnels into it, and direct private calls
    // bypass the public selector entirely.
    const char *selNames[] = {
        "presentViewController:animated:completion:",
        "presentModalViewController:animated:",
        "setRootViewController:",
        "_presentViewController:withAnimationController:completion:",
    };
    SEL sels[4] = {
        sel_registerName(selNames[0]),
        sel_registerName(selNames[1]),
        sel_registerName(selNames[2]),
        sel_registerName(selNames[3]),
    };
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    Class *classes = (Class *)malloc(sizeof(Class) * n);
    n = objc_getClassList(classes, n);
    for (int i = 0; i < n; i++) {
        Class cls = classes[i];
        if (class_isMetaClass(cls)) continue;
        const char *img = class_getImageName(cls);
        if (!img || !strstr(img, "WhatsApp.app/WhatsApp")) continue;
        // v41: setRootViewController: overrides on NON-window classes
        // (coordinators, bottom sheets) re-dispatch the selector on self —
        // patching them made the app loop forever (v40 crash). Only patch
        // real UIWindow subclasses; their orig is never called (we always
        // use the captured UIWindow base IMP instead).
        BOOL isWindowCls = NO;
        if (sels[2]) {
            Class c = cls;
            Class uiwinCls = NSClassFromString(@"UIWindow");
            while (c && c != uiwinCls) c = class_getSuperclass(c);
            isWindowCls = (c == uiwinCls);
        }
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(cls, &mcount);
        if (!methods) continue;
        for (unsigned int mi = 0; mi < mcount; mi++) {
            SEL name = method_getName(methods[mi]);
            IMP cur = method_getImplementation(methods[mi]);
            IMP newImp = NULL;
            if (name == sels[0]) newImp = (IMP)wa_presentVC_block;
            else if (name == sels[1]) newImp = (IMP)wa_presentModalVC_block;
            else if (name == sels[2]) { if (isWindowCls) newImp = (IMP)wa_setRootVC_block; }
            else if (name == sels[3]) newImp = (IMP)wa_presentPrivate_block;
            if (!newImp || cur == newImp) continue;
            // save per-class original (first time only)
            BOOL have = NO;
            for (wa_orig_pres_t *p = g_orig_pres; p; p = p->next)
                if (p->cls == cls && p->sel == name) { have = YES; break; }
            if (!have) {
                wa_orig_pres_t *p = (wa_orig_pres_t *)calloc(1, sizeof(wa_orig_pres_t));
                p->cls = cls; p->sel = name; p->imp = cur;
                p->next = g_orig_pres;
                g_orig_pres = p;
            }
            method_setImplementation(methods[mi], newImp);
            wa_markerOnce([NSString stringWithFormat:@"BYPASS patched %s on %s (present-block)",
                           sel_getName(name), class_getName(cls)]);
        }
        free(methods);
    }
    free(classes);
    // v38: zero the exported low-space flag if it exists
    void *flag = dlsym(RTLD_DEFAULT, "_WACriticallyLowSpaceDidOccur");
    if (flag) {
        *(unsigned char *)flag = 0;
        wa_marker(@"BYPASS zeroed _WACriticallyLowSpaceDidOccur global");
    } else {
        wa_marker(@"BYPASS _WACriticallyLowSpaceDidOccur not exported (dlsym NULL)");
    }
}

static void wa_drive_schedule(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        wa_drive_run();
    });
}

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
    // v34: size cap — once the marker exceeds 3 MB, stop writing (guards
    // against a runaway log storm freezing the main thread).
    const char *home = getenv("HOME");
    if (!home || !home[0]) return;
    char path[1024];
    snprintf(path, sizeof(path), "%s/Documents/wafix_marker.txt", home);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > 3 * 1024 * 1024) {
        close(fd);
        return;
    }
    const char *s = line.UTF8String;
    if (s) {
        size_t n = strlen(s);
        if (n) write(fd, s, n);
        write(fd, "\n", 1);
    }
    close(fd);
}

// v34: fresh marker per launch (truncate at constructor start)
static void wa_marker_reset(void) {
    const char *home = getenv("HOME");
    if (!home || !home[0]) return;
    char path[1024];
    snprintf(path, sizeof(path), "%s/Documents/wafix_marker.txt", home);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) close(fd);
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

// v36: scoped instance swizzle — adds an override ON THE CLASS ITSELF if the
// method is inherited, so we NEVER mutate a superclass implementation
// (class_getInstanceMethod + method_setImplementation on an inherited
// Method would rewrite UIViewController -viewDidAppear: for every VC).
static void wa_swizzle_scoped(Class cls, SEL sel, IMP imp, IMP *origOut) {
    Method m = class_getInstanceMethod(cls, sel);
    const char *types = m ? method_getTypeEncoding(m) : "v@:";
    IMP current = m ? method_getImplementation(m) : NULL;
    if (current == imp) return; // already ours
    if (class_addMethod(cls, sel, imp, types)) {
        // added on cls itself; original = the previously-dispatched (super) IMP
        if (origOut) *origOut = current;
        os_log_info(wa_log(), "scoped-swizzle ADDED -[%s %s]", class_getName(cls), sel_getName(sel));
    } else {
        // already implemented on cls — swap in place
        Method m2 = class_getInstanceMethod(cls, sel);
        if (origOut) *origOut = method_getImplementation(m2);
        method_setImplementation(m2, imp);
        os_log_info(wa_log(), "scoped-swizzle SWAPPED -[%s %s]", class_getName(cls), sel_getName(sel));
    }
}

// v43/v44: image-load callback — fires while dyld is loading images.
// IMPORTANT (v44): do NOT touch the runtime here (objc_getClassList /
// method_setImplementation deadlock with the runtime's load lock — that's
// what hung v43). Set a flag only; the real blocking work is dispatched to
// the main queue, which drains BEFORE application:didFinishLaunching.
static volatile int wa_g_early_ready = 0;
static void wa_on_image_load(const struct mach_header *mh) {
    (void)mh;
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        const char *path = _dyld_get_image_name(i);
        if (!path) continue;
        if (strstr(path, "UIKitCore") || strstr(path, "/UIKit")) {
            wa_g_early_ready = 1;
            return;
        }
    }
}

__attribute__((constructor))
static void wa_init(void) {
    // v34: fresh marker per launch (old log storms could reach 68 MB and
    // freeze the main thread; we only need THIS launch's ground truth)
    wa_marker_reset();
    os_log_info(wa_log(), "waContainerFix v48 constructor running");
    wa_marker(@"=== waContainerFix v48 constructor ===");

    // v43: register an image-load callback — fires the MOMENT UIKitCore (and
    // every other image) loads, which is BEFORE application:didFinishLaunching.
    // Blocking the storage presentation from that instant means the modal
    // NEVER appears and the app proceeds with its NORMAL startup UI.
    // (wa_block_storage_presentation is idempotent; the +2s/+6s blocks below
    // remain as belt-and-braces for late-loaded WhatsApp classes.)
    objc_addLoadImageFunc(wa_on_image_load);
    // v48: THE timing fix. UIApplicationMain calls didFinishLaunching
    // SYNCHRONOUSLY before the main runloop drains — so any main-queue
    // dispatch (even the +0s block) runs AFTER the app presented the storage
    // gate and entered degraded mode. A BACKGROUND queue dispatch blocks on
    // the runtime lock during dyld load, then runs the instant loading
    // finishes — BEFORE main() and didFinishLaunching. Patches land before
    // the startup decision is made.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        wa_marker(@"BYPASS bg-early block running (pre-main)");
        wa_block_storage_presentation();
        wa_neutralize_storage_reads();
        wa_bypass_low_storage();
        wa_kill_storage_on_appear();
        wa_marker(@"BYPASS bg-early block done");
    });
    // v44: +0s main-queue block — drains BEFORE application:didFinishLaunching
    // (UIApplicationMain processes queued main-queue blocks first). If UIKit
    // was already loaded (either order), the presentation block is live before
    // the app can present the storage modal at launch.
    dispatch_async(dispatch_get_main_queue(), ^{
        if (wa_g_early_ready || NSClassFromString(@"UIViewController")) {
            wa_marker(@"BYPASS early block installed (pre-didFinishLaunching)");
            wa_block_storage_presentation();
            wa_bypass_low_storage();
            wa_kill_storage_on_appear();
            wa_neutralize_storage_reads();
        }
    });

    // v32: low-storage gate bypass — run early and retry (classes may not be
    // loaded yet at constructor time), then dismiss any shown modal later
    wa_bypass_low_storage();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        wa_bypass_low_storage();
        wa_dismiss_storage_modal();
        wa_kill_storage_on_appear();
        wa_block_storage_presentation();
        wa_swap_storage_root();
        wa_neutralize_storage_reads();
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        wa_bypass_low_storage();
        wa_dismiss_storage_modal();
        wa_kill_storage_on_appear();
        wa_block_storage_presentation();
        wa_swap_storage_root();
        wa_neutralize_storage_reads();
    });
    // v37/v39: repeating storage-modal kill — the app re-presents the gate on a
    // timer, so keep dismissing + root-swapping every 2 s for the first 2 minutes
    for (int i = 0; i < 60; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)((2 + i * 2) * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            wa_dismiss_storage_modal();
            wa_swap_storage_root();
            // v46: poke the app's OWN recovery path + hard-dismiss the stuck
            // modal from itself (dismissal on the presented VC is legal)
            id app = [(id)NSClassFromString(@"UIApplication") performSelector:NSSelectorFromString(@"sharedApplication")];
            if (app) {
                id windows = [app respondsToSelector:NSSelectorFromString(@"windows")]
                             ? [app performSelector:NSSelectorFromString(@"windows")] : nil;
                for (id w in windows) {
                    id root = [w performSelector:NSSelectorFromString(@"rootViewController")];
                    if (!root) continue;
                    id presented = [root performSelector:@selector(presentedViewController)];
                    if (presented) {
                        SEL dsel = NSSelectorFromString(@"dismissViewControllerAnimated:completion:");
                        if ([presented respondsToSelector:dsel])
                            ((void (*)(id, SEL, BOOL, id))objc_msgSend)(presented, dsel, NO, nil);
                        wa_marker([NSString stringWithFormat:@"BYPASS hard-dismiss %@",
                                   NSStringFromClass(object_getClass(presented))]);
                    }
                    Class chatCls = NSClassFromString(@"WAChatListViewController");
                    if (chatCls && [root isKindOfClass:chatCls]) {
                        SEL rsel = NSSelectorFromString(@"didRecoverFromLowStorage");
                        if ([root respondsToSelector:rsel]) {
                            ((void (*)(id, SEL))objc_msgSend)(root, rsel);
                            wa_marker(@"BYPASS poked didRecoverFromLowStorage");
                        }
                    }
                }
            }
        });
    }

    // v47: force the root to REBUILD its view. Its first loadView ran while
    // the app still believed storage was critical (degraded mode → 0 subviews).
    // Storage reads are all NO now, so a second viewDidLoad may build the real
    // UI. Run at +10s and +30s only (avoid fighting UIKit's own loading).
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        id app = [(id)NSClassFromString(@"UIApplication") performSelector:NSSelectorFromString(@"sharedApplication")];
        id windows = [app respondsToSelector:NSSelectorFromString(@"windows")]
                     ? [app performSelector:NSSelectorFromString(@"windows")] : nil;
        for (id w in windows) {
            id root = [w performSelector:NSSelectorFromString(@"rootViewController")];
            if (!root) continue;
            SEL vdl = NSSelectorFromString(@"viewDidLoad");
            if ([root respondsToSelector:vdl]) {
                ((void (*)(id, SEL))objc_msgSend)(root, vdl);
                wa_marker([NSString stringWithFormat:@"BYPASS re-ran viewDidLoad on %@",
                           NSStringFromClass(object_getClass(root))]);
            }
            id sub = [root performSelector:@selector(view)];
            NSArray *subs = [sub respondsToSelector:NSSelectorFromString(@"subviews")]
                            ? [sub performSelector:NSSelectorFromString(@"subviews")] : nil;
            wa_marker([NSString stringWithFormat:@"BYPASS post-rebuild subviews: %lu",
                       (unsigned long)[subs count]]);
        }
    });
    // v31: schedule the in-app UI driver (registration drive) — reads
    // Documents/wafix_drive.txt at +8s (DUMP/TYPE/TAP/STATS commands)
    wa_drive_schedule();

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
