## Makefile.am

AM_CPPFLAGS = ${libuuid_CFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = -Wall
sbin_PROGRAMS = fsck.f2fs
fsck_f2fs_SOURCES = main.c fsck.c dump.c mount.c
fsck_f2fs_LDADD = ${libuuid_LIBS} $(top_builddir)/lib/libf2fs.la

install-data-hook:
	ln -sf fsck.f2fs $(DESTDIR)/$(sbindir)/dump.f2fs
