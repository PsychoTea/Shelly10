//
//  ViewController.m
//  Shelly10
//
//  Created by Ben Sparkes on 01/06/2018.
//  Copyright © 2018 Ben Sparkes. All rights reserved.
//

#import "ViewController.h"
#include <mach/mach_types.h>
#include <sys/stat.h>
#include "kernel.h"
#include "offsetfinder.h"
#include "common.h"
#include "libkern.h"
#include "amfi.h"
#include "patchfinder64.h"
#include "root-rw.h"
#include "helpers.h"
#include "untar.h"

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *goButton;
@property (weak, nonatomic) IBOutlet UIActivityIndicatorView *spinnyWheel;
@property (weak, nonatomic) IBOutlet UITextView *textArea;
@end

@implementation ViewController

offsets_t offsets;
task_t tfp0;
uint64_t kernel_base;
uint64_t kslide;
uint64_t kernprocaddr;
uint64_t kern_ucred;
BOOL hasRun = false;

- (void)viewDidLoad {
    [super viewDidLoad];
    
    [self.spinnyWheel setHidden:TRUE];
}

- (IBAction)goButtonPressed:(id)sender {
    
    if (hasRun) {
        // cleanup
        [[NSFileManager defaultManager] removeItemAtPath:@"/shelly" error:nil];
        [self writeText:@"cleaned."];
        return;
    }
    
    [self writeText:@"woooo we're going!!"];
    
    [self.spinnyWheel setHidden:FALSE];
    [self.spinnyWheel startAnimating];
    
    int ret;
    
    host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
    if (MACH_PORT_VALID(tfp0)) {
        [self writeText:@"got some tfp0"];
        kernel_base = get_kernel_base();
        kslide = kernel_base - 0xFFFFFFF007004000;
    } else {
        ret = runV0rtex();
        if (ret != 0) {
            [self writeText:@"Failed to run v0rtex :("];
            [self failure];
            return;
        }
        [self writeText:@"v0rtex ran."];
    }
    
    [self writeText:[NSString stringWithFormat:@"slide: %llx", kslide]];
    
    // init stuff
    init_patchfinder(NULL);
    ret = init_amfi();
    
    // remount FS as r/w
    ret = remountRootFs();
    if (ret != 0 &&
        ret != -61 &&
        ret != -62) {
        [self writeText:[NSString stringWithFormat:@"failed to remount: %d", ret]];
        [self failure];
        return;
    }
    
    mkdir("/shelly", 0755);
    chdir("/shelly");
    
    const char *bootstrap_path = bundled_file("bootstrap.tar");
    
    untar(fopen(bootstrap_path, "r"), "/shelly");

    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/shelly/bins" error:nil];
    for (NSString *file in files) {
        NSString *fullPath = [NSString stringWithFormat:@"/shelly/bins/%@", file];
        inject_trust([fullPath UTF8String]);
        NSLog(@"trusted: %@", fullPath);
    }
    
    if (access("/bin/sh", F_OK) != 0) {
        symlink("/shelly/bins/bash", "/bin/sh");
    } else {
        inject_trust("/bin/sh");
        inject_trust("/bin/bash");
    }
    
    // other random shell bullshit
    inject_trust("/usr/lib/libreadline.6.0.dylib");
    inject_trust("/usr/lib/libhistory.6.0.dylib");
    inject_trust("/usr/lib/libncurses.5.dylib");
    
    // bullshit for dropbear
    mkdir("/etc/dropbear", 0755);
    mkdir("/var/log", 0755);
    fclose(fopen("/var/log/lastlog", "w+"));
    
    const char *args[] = (const char *[]) {
        "/shelly/bins/dropbear",
        "-p",
        "22",
        "-p",
        "2222",
        "-R",
        "-E",
        "-m",
        "-S",
        "/",
        NULL
    };
    execprog("/shelly/bins/dropbear", args);
    [self writeText:@"launched dropbear."];
    hasRun = true;
    [self.goButton setTitle:@"clean me up daddy!" forState:UIControlStateNormal];
}

kern_return_t callback(task_t kern_task, kptr_t kbase, void *cb_data) {
    tfp0 = kern_task;
    kernel_base = kbase;
    kslide = kernel_base - 0xFFFFFFF007004000;
    
    return KERN_SUCCESS;
}

int runV0rtex() {
    offsets_t *offs = get_offsets();
    
    if (offs == NULL) {
        return -420;
    }
    
    offsets = *offs;
    
    int ret = v0rtex(&offsets, &callback, NULL);
    
    uint64_t kernel_task_addr = rk64(offs->kernel_task + kslide);
    kernprocaddr = rk64(kernel_task_addr + offs->task_bsd_info);
    kern_ucred = rk64(kernprocaddr + offs->proc_ucred);
    
    if (ret == 0) {
        NSLog(@"tfp0: 0x%x", tfp0);
        NSLog(@"kernel_base: 0x%llx", kernel_base);
        NSLog(@"kslide: 0x%llx", kslide);
        NSLog(@"kern_ucred: 0x%llx", kern_ucred);
        NSLog(@"kernprocaddr: 0x%llx", kernprocaddr);
    }
    
    return ret;
}

int remountRootFs() {
    NSOperatingSystemVersion osVersion = [[NSProcessInfo processInfo] operatingSystemVersion];
    int pre130 = osVersion.minorVersion < 3 ? 1 : 0;
    
    return mount_root(kslide, offsets.root_vnode, pre130);
}

- (void)failure {
    [self.spinnyWheel setHidden:TRUE];
}

- (void)writeText:(NSString *)message {
    NSString *currText = [self.textArea text];
    currText = [NSString stringWithFormat:@"%@%@\n", currText, message];
    [self.textArea setText:currText];
}

@end
