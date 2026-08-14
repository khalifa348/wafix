// ME72 minimal test dylib — marker + test hooks ONLY.
// NO dyld interpose, NO resolver swizzle, NO NSURL/NSFileManager/NSDictionary swizzles,
// NO country-DB synthesis, NO hiding. ME71b proved machinery-free loads clean.
// Goal: drive the 3 emulation-proven leads with crafted values on-device.
//
// Strategy: hook the vulnerable entry points via ObjC method swizzling ONLY
// (no dyld interpose), feed out-of-range values, log what happens to marker file.
// If a crafted value crashes the app -> on-device proof of the lead.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>

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

// ---------------------------------------------------------------------------
// Test hooks: we ONLY swizzle to OBSERVE (call original), except the "trigger"
// round which deliberately feeds a crafted value. Controlled by marker file
// contents: "TRIGGER:1" enables crafted input for lead 1.
// ---------------------------------------------------------------------------

// Lead 1: XMPPConnectionMain processPersistedStanza: — NEW build indexes a block
// field with NO bounds check (emulation-proven: OOB byte offsets fault).
// On the OLD build (26.22.76 = our base), the guard EXISTS (cmp #9; b.hi).
// We can't reproduce the NEW-bug on OLD base directly; instead we verify the
// OLD guard actually blocks (sanity) and prepare the call path for the 26.30.77
// baseline later. For now: instrument and log.

static void (*orig_processPersistedStanza)(id, SEL, id);
static void hook_processPersistedStanza(id self, SEL _cmd, id stanza) {
    wa_marker([NSString stringWithFormat:@"[hook] processPersistedStanza: stanza=%@", stanza ? NSStringFromClass([stanza class]) : @"nil"]);
    orig_processPersistedStanza(self, _cmd, stanza);
}

// Lead 2: preprocessRekeyStanza:completion: — NEW added guard cmp #2; b.lo.
// OLD (our base) had NO check at the equivalent spot -> feed a rekey stanza with
// low count to see if OLD handles it (it should, no crash) — documents the delta.
static void (*orig_preprocessRekey)(id, SEL, id, id);
static void hook_preprocessRekey(id self, SEL _cmd, id stanza, id completion) {
    wa_marker(@"[hook] preprocessRekeyStanza:completion: called");
    orig_preprocessRekey(self, _cmd, stanza, completion);
}

// Lead 3: WAMessageDecryptionProcessor processMessage: — OLD used cmp #3; b.hi
// jump table, NEW object-dispatch + null-check. Instrument calls.
static void (*orig_processMessage)(id, SEL, id);
static void hook_processMessage(id self, SEL _cmd, id msg) {
    wa_marker(@"[hook] processMessage: called");
    orig_processMessage(self, _cmd, msg);
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

__attribute__((constructor))
static void waInit(void) {
    @autoreleasepool {
        wa_marker(@"=== waContainerFix ME72 (minimal, no machinery) constructor ===");

        // Classes may not exist at constructor time on newer iOS; retry lazily
        // from a dispatch_after since we are in the app's main thread context.
        // Simple approach: try now, and again in 5s / 15s.
        for (int attempt = 0; attempt < 3; attempt++) {
            Class c1 = NSClassFromString(@"XMPPConnectionMain");
            Class c2 = NSClassFromString(@"WAIncomingStanzaProcessor"); // rekey owner (verify at runtime)
            Class c3 = NSClassFromString(@"WAMessageDecryptionProcessor");
            if (c1) wa_swizzle(c1, NSSelectorFromString(@"processPersistedStanza:"), (IMP)hook_processPersistedStanza, (void **)&orig_processPersistedStanza);
            if (c2) wa_swizzle(c2, NSSelectorFromString(@"preprocessRekeyStanza:completion:"), (IMP)hook_preprocessRekey, (void **)&orig_preprocessRekey);
            if (c3) wa_swizzle(c3, NSSelectorFromString(@"processMessage:"), (IMP)hook_processMessage, (void **)&orig_processMessage);
            int hooked = (orig_processPersistedStanza ? 1 : 0) + (orig_preprocessRekey ? 1 : 0) + (orig_processMessage ? 1 : 0);
            if (hooked == 3) break;
            wa_marker([NSString stringWithFormat:@"[init] attempt %d: %d/3 classes hooked", attempt + 1, hooked]);
            usleep(5000000);
        }
        wa_marker(@"[init] ME72 constructor complete");
    }
}
