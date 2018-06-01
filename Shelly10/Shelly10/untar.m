/*
 * "untar" is an extremely simple tar extractor:
 *  * A single C source file, so it should be easy to compile
 *    and run on any system with a C compiler.
 *  * Extremely portable standard C.  The only non-ANSI function
 *    used is mkdir().
 *  * Reads basic ustar tar archives.
 *  * Does not require libarchive or any other special library.
 *
 * To compile: cc -o untar untar.c
 *
 * Usage:  untar <archive>
 *
 * In particular, this program should be sufficient to extract the
 * distribution for libarchive, allowing people to bootstrap
 * libarchive on systems that do not already have a tar program.
 *
 * To unpack libarchive-x.y.z.tar.gz:
 *    * gunzip libarchive-x.y.z.tar.gz
 *    * untar libarchive-x.y.z.tar
 *
 * Written by Tim Kientzle, March 2009.
 * Modified by xerub, sometime in 2017.
 *
 * Released into the public domain.
 */

/* These are all highly standard and portable headers. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* This is for mkdir(); this may need to be changed for some platforms. */
#include <sys/stat.h>  /* For mkdir() */

#include <Foundation/Foundation.h>

/* Parse an octal number, ignoring leading and trailing nonsense. */
static int
parseoct(const char *p, size_t n)
{
	int i = 0;

	while (*p < '0' || *p > '7') {
		++p;
		--n;
	}
	while (*p >= '0' && *p <= '7' && n > 0) {
		i *= 8;
		i += *p - '0';
		++p;
		--n;
	}
	return (i);
}

/* Returns true if this is 512 zero bytes. */
static int
is_end_of_archive(const char *p)
{
	int n;
	for (n = 511; n >= 0; --n)
		if (p[n] != '\0')
			return (0);
	return (1);
}

/* Create a directory, including parent directories as necessary. */
static void
create_dir(char *pathname, int mode, int owner, int group)
{
	char *p;
	int r;

	struct stat st;
	r = stat(pathname, &st);
	if (r == 0) {
		return;
	}

	/* Strip trailing '/' */
	if (pathname[strlen(pathname) - 1] == '/')
		pathname[strlen(pathname) - 1] = '\0';

	/* Try creating the directory. */
	r = mkdir(pathname, mode);

	if (r != 0) {
		/* On failure, try creating parent directory. */
		p = strrchr(pathname, '/');
		if (p != NULL) {
			*p = '\0';
			create_dir(pathname, 0755, -1, -1);
			*p = '/';
			r = mkdir(pathname, mode);
		}
	}
	if (r != 0)
		NSLog(@"Could not create directory %s", pathname);
	else if (owner >= 0 && group >= 0)
		chown(pathname, owner, group);
}

/* Create a file, including parent directory as necessary. */
static int
create_file(char *pathname, int mode, int owner, int group)
{
	int f;
	if (unlink(pathname) && errno != ENOENT) {
		return -1;
	}
	f = creat(pathname, mode);
	if (f < 0) {
		/* Try creating parent dir and then creating file. */
		char *p = strrchr(pathname, '/');
		if (p != NULL) {
			*p = '\0';
			create_dir(pathname, 0755, -1, -1);
			*p = '/';
			f = creat(pathname, mode);
		}
	}
	fchown(f, owner, group);
	return (f);
}

/* Verify the tar checksum. */
static int
verify_checksum(const char *p)
{
	int n, u = 0;
	for (n = 0; n < 512; ++n) {
		if (n < 148 || n > 155)
			/* Standard tar checksum adds unsigned bytes. */
			u += ((unsigned char *)p)[n];
		else
			u += 0x20;

	}
	return (u == parseoct(p + 148, 8));
}

/* Extract a tar archive. */
int
untar(FILE *a, const char *path)
{
	char buff[512];
	int f = -1;
	size_t bytes_read;
	int filesize;

	NSLog(@"Extracting from %s", path);
	for (;;) {
		bytes_read = fread(buff, 1, 512, a);
		if (bytes_read < 512) {
			NSLog(@"Short read on %s: expected 512, got %d", path, (int)bytes_read);
			return -1;
		}
		if (is_end_of_archive(buff)) {
			NSLog(@"End of %s", path);
			return 0;
		}
		if (!verify_checksum(buff)) {
			NSLog(@"Checksum failure");
			return -2;
		}
		filesize = parseoct(buff + 124, 12);
		switch (buff[156]) {
		case '1':
			NSLog(@" Ignoring hardlink %s", buff);
			break;
		case '2':
			NSLog(@" Extracting symlink %s -> %s", buff, buff + 157);
			if (unlink(buff) && errno != ENOENT) {
				break;
			}
			symlink(buff + 157, buff);
			break;
		case '3':
			NSLog(@" Ignoring character device %s", buff);
				break;
		case '4':
			NSLog(@" Ignoring block device %s", buff);
			break;
		case '5':
			NSLog(@" Extracting dir %s", buff);
			create_dir(buff, parseoct(buff + 100, 8), parseoct(buff + 108, 8), parseoct(buff + 116, 8));
			filesize = 0;
			break;
		case '6':
			NSLog(@" Ignoring FIFO %s", buff);
			break;
		default:
			NSLog(@" Extracting file %s", buff);
			f = create_file(buff, parseoct(buff + 100, 8), parseoct(buff + 108, 8), parseoct(buff + 116, 8));
			break;
		}
		while (filesize > 0) {
			bytes_read = fread(buff, 1, 512, a);
			if (bytes_read < 512) {
				NSLog(@"Short read on %s: Expected 512, got %zd", path, bytes_read);
				return -3;
			}
			if (filesize < 512)
				bytes_read = filesize;
			if (f >= 0) {
				if (write(f, buff, bytes_read)
				    != bytes_read)
				{
					NSLog(@"Failed write");
					close(f);
					f = -1;
				}
			}
			filesize -= bytes_read;
		}
		if (f >= 0) {
			close(f);
			f = -1;
		}
	}
    
    return 0;
}
