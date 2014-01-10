## Makefile.am

AM_CPPFLAGS = ${libuuid_CFLAGS} -I$(top_srcdir)/include
AM_CFLAGS = -Wall
sbin_PROGRAMS = f2fstat
f2fstat_SOURCES = f2fstat.c
f2fstat_LDADD = ${libuuid_LIBS} $(top_builddir)/lib/libf2fs.la
