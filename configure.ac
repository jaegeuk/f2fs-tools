#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([F2FS tools], [1.0.0], [TBD])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([mkfs/f2fs_format.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([uuid], [uuid_generate],
	[AC_DEFINE([HAVE_LIBUUID], 1,
	  [Define to 1 if you have the 'uuid' library (-luuid).])],
	[AC_MSG_ERROR([UUID library not found])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h mntent.h stdlib.h string.h sys/ioctl.h sys/mount.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_GETMNTENT
AC_CHECK_FUNCS([getmntent memset])

AC_CONFIG_FILES([Makefile
                 man/Makefile
                 mkfs/Makefile])
AC_OUTPUT
