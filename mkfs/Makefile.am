## Makefile.am

AM_CPPFLAGS = ${libuuid_CFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = -Wall -DWITH_BLKDISCARD
sbin_PROGRAMS = mkfs.f2fs
mkfs_f2fs_SOURCES = f2fs_format_main.c f2fs_format.c f2fs_format_utils.c
mkfs_f2fs_LDADD = ${libuuid_LIBS} $(top_builddir)/lib/libf2fs.la
