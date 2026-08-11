// wa_container_fix.m — WhatsAppSMB sideload fix dylib.
// The sideload provisioning profile has NO com.apple.security.application-groups
// entitlement, so -[NSFileManager containerURLForSecurityApplicationGroupIdentifier:]
// returns nil. WhatsApp's [super initWithDependenciesInjected] (SharedModules) then
// does [NSURL fileURLWithPath: nil] -> NSInvalidArgumentException crash (ME25), and
// even when skipped the country-DB global never loads (ME26/ME27 hang).
//
// Fix: swizzle that method to return the app's OWN sandbox container
// (NSHomeDirectory — always exists, always writable) for any group ID.
// The app then happily creates its dirs/files inside its own container.

#import <Foundation/Foundation.h>
#import <objc/runtime.h>

static NSURL *wa_fake_container(id self, SEL _cmd, NSString *groupIdentifier) {
    (void)self; (void)_cmd; (void)groupIdentifier;
    return [NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES];
}

__attribute__((constructor))
static void wa_install_swizzle(void) {
    Method m = class_getInstanceMethod([NSFileManager class],
        @selector(containerURLForSecurityApplicationGroupIdentifier:));
    if (m) {
        class_replaceMethod([NSFileManager class],
            @selector(containerURLForSecurityApplicationGroupIdentifier:),
            (IMP)wa_fake_container, method_getTypeEncoding(m));
    }
}
