## Makefile.am

AM_CPPFLAGS = ${libuuid_CFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = -Wall
sbin_PROGRAMS = mkfs.f2fs
mkfs_f2fs_SOURCES = f2fs_format.c
mkfs_f2fs_LDFLAGS = -all-static
mkfs_f2fs_LDADD = ${libuuid_LIBS} $(top_builddir)/lib/libf2fs.la
