# Makefile.am for ps3tools
#
# (C) Youness Alaoui (KaKaRoTo)
#
# Licensed under LGPL 2.1. See file COPYING.

AUTOMAKE_OPTIONS = subdir-objects

ERROR_CFLAGS = \
	$(PS3TOOLS_CFLAGS) \
	-fno-strict-aliasing \
	-Wextra \
	-Wundef \
	-Wnested-externs \
	-Wwrite-strings \
	-Wpointer-arith \
	-Wbad-function-cast \
	-Wmissing-declarations \
	-Wmissing-prototypes \
	-Wstrict-prototypes \
	-Wredundant-decls \
	-Wno-unused-parameter \
	-Wno-missing-field-initializers

AM_CFLAGS = \
	$(ERROR_CFLAGS) \
	$(ZLIB_CFLAGS)

bin_PROGRAMS = 	sceverify \
		readself \
		readself2 \
		unself \
		unself2 \
		makeself \
		self_rebuilder \
		ungpkg \
		norunpack \
		pupunpack \
		puppack \
		unpkg \
		pkg \
		cosunpkg \
		cospkg \
		cosunpack \
		undat \
		dat \
		unspp \
		eidsplitr \
		spp \
		scetool

bin_SCRIPTS = pupexplode \
		ebootromexplode \
		ebootromexplodedec \
		ebootromexplode060 

if HAVE_LIBGMP
    bin_PROGRAMS += scekrit
endif

SELF_DEPS = 	self.c \
		self.h \
		common.h

COMMON_DEPS =  types.h \
		tools.c \
		tools.h \
		aes.c \
		aes.h \
		sha1.c \
		sha1.h \
		ec.c \
		bn.c \
		mingw_mmap.c \
		mingw_mmap.h
		
SCETOOL_DEPS = scetool_src/aes.cpp \
		scetool_src/aes_omac.h \
		scetool_src/ecdsa.h \
		scetool_src/getopt.cpp \
		scetool_src/list.h \
		scetool_src/np.h \
		scetool_src/sce.cpp \
		scetool_src/sha1.cpp \
		scetool_src/tables.h \
		scetool_src/zlib.h \
		scetool_src/bn.cpp \
		scetool_src/elf.h \
		scetool_src/getopt.h \
		scetool_src/pkg.cpp \
		scetool_src/sce.h \
		scetool_src/sha1.h \
		scetool_src/types.h \
		scetool_src/config.h \
		scetool_src/elf_inlines.h \
		scetool_src/keys.cpp \
		scetool_src/mt19937.cpp \
		scetool_src/pkg.h \
		scetool_src/sce_inlines.h \
		scetool_src/spp.cpp \
		scetool_src/util.cpp \
		scetool_src/aes.h \
		scetool_src/ec.cpp \
		scetool_src/frontend.cpp \
		scetool_src/keys.h \
		scetool_src/mt19937.h \
		scetool_src/rvk.cpp \
		scetool_src/self.cpp \
		scetool_src/spp.h \
		scetool_src/util.h \
		scetool_src/aes_omac.cpp \
		scetool_src/ecdsa.cpp \
		scetool_src/frontend.h \
		scetool_src/list.cpp \
		scetool_src/np.cpp \
		scetool_src/rvk.h \
		scetool_src/self.h \
		scetool_src/tables.cpp \
		scetool_src/zconf.h \
		scetool_src/main.cpp
		

scetool_SOURCES = $(SCETOOL_DEPS) 
		

sceverify_SOURCES = $(COMMON_DEPS) \
		sceverify.c

readself_SOURCES = $(COMMON_DEPS) \
		readself.c

readself2_SOURCES = $(COMMON_DEPS) \
		readself2.c

unself_SOURCES = $(COMMON_DEPS) \
		unself.c

unself2_SOURCES = $(COMMON_DEPS) \
		$(SELF_DEPS) \
		unself2.c

makeself_SOURCES = $(COMMON_DEPS) \
		makeself.c

self_rebuilder_SOURCES = $(COMMON_DEPS) \
		self_rebuilder.c

ungpkg_SOURCES = $(COMMON_DEPS) \
		ungpkg.c

norunpack_SOURCES = $(COMMON_DEPS) \
		norunpack.c

pupunpack_SOURCES = $(COMMON_DEPS) \
		pupunpack.c

puppack_SOURCES = $(COMMON_DEPS) \
		puppack.c

unpkg_SOURCES = $(COMMON_DEPS) \
		unpkg.c

pkg_SOURCES = $(COMMON_DEPS) \
		pkg.c

cosunpkg_SOURCES = $(COMMON_DEPS) \
		cosunpkg.c

cospkg_SOURCES = $(COMMON_DEPS) \
		cospkg.c

cosunpack_SOURCES = $(COMMON_DEPS) \
		cosunpack.c

undat_SOURCES = $(COMMON_DEPS) \
		undat.c

dat_SOURCES = $(COMMON_DEPS) \
		dat.c

unspp_SOURCES = $(COMMON_DEPS) \
		unspp.c

eidsplitr_SOURCES = $(COMMON_DEPS) \
		eidsplitr.c

scekrit_SOURCES = $(COMMON_DEPS) \
		scekrit.c
scekrit_LDADD = $(GMP_LIBS)

spp_SOURCES = $(COMMON_DEPS) \
	      spp.c
		unspp.c
