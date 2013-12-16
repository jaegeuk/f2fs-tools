F2FS format utilility
---------------------

To use f2fs filesystem, you should format the storage partition
with this utilility. Otherwise, you cannot mount f2fs.

Before compilation
------------------

Your should install the following packages.
 - libuuid-devel or uuid-dev
 - pkg-config
 - autoconf
 - libtool

Initial compilation
-------------------

Before compilation initially, autoconf/automake tools should be run.

 # autoreconf --install

How to compile
--------------

 # ./configure
 # make

How to cross-compile (e.g., for ARM)
------------------------------------

 1. Add the below line into mkfs/Makefile.am:
 mkfs_f2fs_LDFLAGS = -all-static

 2. Add the below line into fsck/Makefile.am:
 fsck_f2fs_LDFLAGS = -all-static

 3. then, do:
 # LDFLAGS=--static ./configure \
	--host=arm-none-linux-gnueabi --target=arm-none-linux-gnueabi
 # make

How to run by default
---------------------

 $ ./mkfs.f2fs -l [LABEL] $DEV

For more mkfs options, see man page.
