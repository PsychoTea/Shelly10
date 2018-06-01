/*
 * libkern.h - Everything that touches the kernel.
 *
 * Copyright (c) 2014 Samuel Groß
 * Copyright (c) 2016-2017 Siguza
 */

#ifndef LIBKERN_H
#define LIBKERN_H

#include <stdio.h>              // fprintf, stderr
#include <unistd.h>             // geteuid

#include <mach/kern_return.h>   // kern_return_t
#include <mach/mach_error.h>    // mach_error_string
#include <mach/mach_types.h>    // task_t
#include <mach/port.h>          // MACH_PORT_NULL, MACH_PORT_VALID
#include <mach/vm_types.h>      // vm_address_t, vm_size_t

/*
 * Functions and macros to interact with the kernel address space.
 *
 * If not otherwise stated the following functions are 'unsafe', meaning
 * they are likely to panic the device if given invalid kernel addresses.
 *
 * You have been warned.
 */

/*
 * Get the kernel task port.
 *
 * This function should be safe.
 */

kern_return_t get_kernel_task(task_t *task);

/*
 * Return the base address of the running kernel.
 *
 * This function should be safe at least on iOS 9 and earlier.
 */
vm_address_t get_kernel_base(void);

/*
 * Read data from the kernel address space.
 *
 * Returns the number of bytes read.
 */
vm_size_t kernel_read(vm_address_t addr, vm_size_t size, void *buf);

/*
 * Write data into the kernel address space.
 *
 * Returns the number of bytes written.
 */
vm_size_t kernel_write(vm_address_t addr, vm_size_t size, void *buf);

/*
 * Find the given byte sequence in the kernel address space between start and end.
 *
 * Returns the address of the first occurance of bytes if found, otherwise 0.
 */
vm_address_t kernel_find(vm_address_t addr, vm_size_t len, void *buf, size_t size);

/*
 * Test for kernel task access and return -1 on failure.
 *
 * To be embedded in a main() function.
 *
 * If parameters are given, the last one will be assigned the kernel task, all others are ignored.
 */
#define KERNEL_TASK_OR_GTFO(args...) \
do \
{ \
    task_t _kernel_task = MACH_PORT_NULL; \
    kern_return_t _ret = get_kernel_task(&_kernel_task); \
    _kernel_task, ##args = _kernel_task; /* mad haxx */ \
    if(_ret != KERN_SUCCESS || !MACH_PORT_VALID(_kernel_task)) \
    { \
        fprintf(stderr, "[!] Failed to get kernel task (%s, kernel_task = %x)\n", mach_error_string(_ret), _kernel_task); \
        if(_ret != KERN_SUCCESS && geteuid() != 0) \
        { \
            fprintf(stderr, "[!] But you are not root, either. Try again as root.\n"); \
        } \
        return -1; \
    } \
} while(0)

/*
 * Test for kernel base address and return -1 if it cannot be determined.
 *
 * To be embedded in a main() function.
 */
#define KERNEL_BASE_OR_GTFO(base) \
do \
{ \
    KERNEL_TASK_OR_GTFO(); \
    if((base = get_kernel_base()) == 0) \
    { \
        fprintf(stderr, "[!] Failed to locate kernel\n"); \
        return -1; \
    } \
} while(0)

#endif
