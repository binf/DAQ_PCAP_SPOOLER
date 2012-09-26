#												-*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([daq_pcap_spooler], [0.2], [beenph@gmail.com])
AM_INIT_AUTOMAKE([daq], [0.2])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([daq_pcap_spooler.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Enable visibility if we can
AC_ENABLE_VISIBILITY()
# Special compiler flags for ICC, etc.
AC_SF_COMPILER_SETUP()

# Checks for the DAQ API headers and the SFBPF headers/library.
AC_CHECK_DAQ_API
AC_CHECK_SFBPF

# Checks for other dependencies of your DAQ module go here.

# Large file support
AC_ARG_ENABLE(largefile,
            [  --enable-largefile  Enable largefile support (default:no)],
            [enable_largefile="yes"], [enable_largefile="no"])

if test "x$enable_largefile" == "xyes"; then
  CPPFLAGS="${CPPFLAGS} -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64"
  AC_TYPE_INT64_T
  AC_CHECK_FUNCS([lseek64 fstat64])
  AC_DEFINE([LARGEFILE_SUPPORT],[1],[We support large file])
else
  AC_CHECK_FUNCS([lseek fstat])
fi

# Large file support

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h pcap.h bpf.h daq_api.h sfbpf_dlt.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strchr strdup strerror strtol])

# Substitutions

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
