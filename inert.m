// inert.m — ME71 CONTROL: does NOTHING except write a marker.
// No dyld interpose, no resolver swizzle, no NSURL/NSFileManager/NSDictionary
// swizzles, no country-DB synthesis. Answers: is the BaseBoard
// _BSXPCAutoCodingInitialize launch trap caused by OUR machinery or by the
// ME34 base binary itself (its ~100 mov-x0/#0 ret anti-tamper patches)?
#import <Foundation/Foundation.h>

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

__attribute__((constructor))
static void wa_inert_init(void) {
    wa_marker(@"=== waContainerFix INERT (ME71 control, no machinery) ===");
}
