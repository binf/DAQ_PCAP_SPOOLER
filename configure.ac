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
AC_CHECK_FUNCS([daq_hup_apply] [daq_acquire_with_meta])


# Couldn't really find a better way to do this.

AC_DEFUN([AC_CHECK_DAQ_API_VER],
[
AC_MSG_CHECKING([DAQ_API_VERSION])
AC_LINK_IFELSE([
  AC_LANG_SOURCE(
  [[
     #include <daq_api.h>
     int main()
     {	  
     #ifdef DAQ_API_VERSION
     if(DAQ_API_VERSION == $1)
           {
             return 0;
           }
     #endif
	 return 1;
     }]])],
	   [
	   AC_MSG_RESULT([DAQ_API_VERSION installed is ($1) OK ])
	   ],
	   [
	    AC_MSG_RESULT([DAQ_API_VERSION installed is not ($1) ERROR ])
	    exit 1;
	   ])
])

AC_CHECK_DAQ_API_VER([0x00010002])


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

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h pcap.h bpf.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strchr strdup strerror strtol])

# Substitutions

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
