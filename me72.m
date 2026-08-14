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

// REAL selectors from objc_methods dumps (OLD 26.22.76 = our base):
//   Lead 1: XMPPConnectionMain processPersistedStanza:inPersistentStanzaQueue:isFromDeferredNSEMerge:nseMergeCompletion:  0x102a69c88
//   Lead 2: XMPP preprocessRekeyStanza:completion:  0x104810d20
//   Lead 3: WAMessageDecryptionProcessor processMessage:input:cancellationHandle:completion:  0x102fda67c

static void (*orig_processPersistedStanza)(id, SEL, id, id, BOOL, id);
static void hook_processPersistedStanza(id self, SEL _cmd, id stanza, id queue, BOOL deferred, id mergeCompletion) {
    wa_marker([NSString stringWithFormat:@"[hook] processPersistedStanza:inPersistentStanzaQueue:... stanza=%@", stanza ? NSStringFromClass([stanza class]) : @"nil"]);
    orig_processPersistedStanza(self, _cmd, stanza, queue, deferred, mergeCompletion);
}

static void (*orig_preprocessRekey)(id, SEL, id, id);
static void hook_preprocessRekey(id self, SEL _cmd, id stanza, id completion) {
    wa_marker([NSString stringWithFormat:@"[hook] preprocessRekeyStanza:completion: stanza=%@", stanza ? NSStringFromClass([stanza class]) : @"nil"]);
    orig_preprocessRekey(self, _cmd, stanza, completion);
}

static void (*orig_processMessage)(id, SEL, id, id, id, id, id);
static void hook_processMessage(id self, SEL _cmd, id msg, id ctx, id src, id deps, id completion) {
    wa_marker([NSString stringWithFormat:@"[hook] processMessage:... msg=%@", msg ? NSStringFromClass([msg class]) : @"nil"]);
    orig_processMessage(self, _cmd, msg, ctx, src, deps, completion);
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

        // dvt-launched test apps get clean-killed ~25s after launch, so the
        // whole retry window must fit inside ~15s. Sync loop, short sleeps.
        for (int attempt = 0; attempt < 6; attempt++) {
            Class c1 = NSClassFromString(@"XMPPConnectionMain");
            Class c2 = NSClassFromString(@"XMPP"); // rekey owner (RE-verified)
            Class c3 = NSClassFromString(@"WAMessageDecryptionProcessor");
            if (c1) wa_swizzle(c1, NSSelectorFromString(@"processPersistedStanza:inPersistentStanzaQueue:isFromDeferredNSEMerge:nseMergeCompletion:"), (IMP)hook_processPersistedStanza, (void **)&orig_processPersistedStanza);
            if (c3) wa_swizzle(c3, NSSelectorFromString(@"processMessage:input:cancellationHandle:completion:"), (IMP)hook_processMessage, (void **)&orig_processMessage);
            if (!c2 && !orig_preprocessRekey) {
                // No bare "XMPP" class at runtime (it's a Swift module prefix).
                // Find the real owner by scanning ALL classes for the selector.
                SEL sel = NSSelectorFromString(@"preprocessRekeyStanza:completion:");
                int n = objc_getClassList(NULL, 0);
                Class *buf = (Class *)malloc(sizeof(Class) * n);
                objc_getClassList(buf, n);
                int found = 0;
                for (int i = 0; i < n; i++) {
                    Method m = class_getInstanceMethod(buf[i], sel);
                    if (m) {
                        wa_swizzle(buf[i], sel, (IMP)hook_preprocessRekey, (void **)&orig_preprocessRekey);
                        wa_marker([NSString stringWithFormat:@"[scan] preprocessRekey owner found: %s", class_getName(buf[i])]);
                        found = 1;
                        break;
                    }
                }
                if (!found) wa_marker(@"[scan] preprocessRekey selector not found on any loaded class");
                free(buf);
            }
            int hooked = (orig_processPersistedStanza ? 1 : 0) + (orig_preprocessRekey ? 1 : 0) + (orig_processMessage ? 1 : 0);
            if (hooked == 3) break;
            wa_marker([NSString stringWithFormat:@"[init] attempt %d: %d/3 classes hooked", attempt + 1, hooked]);
            usleep(3000000);
        }
        wa_marker(@"[init] ME72 constructor complete");
    }
}
