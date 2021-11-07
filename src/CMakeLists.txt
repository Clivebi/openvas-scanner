# Copyright (C) 2011-2021 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

## Program

## Dependency checks

include (FindPkgConfig)

if (NOT PKG_CONFIG_FOUND)
  message(FATAL_ERROR "pkg-config executable not found. Aborting.")
endif (NOT PKG_CONFIG_FOUND)

pkg_check_modules (LIBGVM_BASE REQUIRED libgvm_base>=21.4.1)
pkg_check_modules (LIBGVM_BOREAS REQUIRED libgvm_boreas>=21.4.1)
pkg_check_modules (LIBGVM_UTIL REQUIRED libgvm_util>=21.4.1)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules (LIBNET REQUIRED libnet>=1.2)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules (GIO REQUIRED gio-2.0)
pkg_check_modules (GNUTLS REQUIRED gnutls>=3.2.15)

pkg_check_modules (OPENVAS_WMICLIENT libopenvas_wmiclient>=1.0.5)
pkg_check_modules (OPENVAS_WINCMD libopenvas_wincmd>=1.0.5)

# for kb we need libhiredis
pkg_check_modules (REDIS REQUIRED hiredis>=0.10.1)

# for fast XML we need libxml2
pkg_check_modules (LIBXML2 REQUIRED libxml-2.0>=2.0)
pkg_check_modules (ZLIB REQUIRED zlib>=1.2.8)

pkg_check_modules (GIO REQUIRED gio-2.0>=2.42)
# for 'nasl' binary
pkg_check_modules (LIBSSH REQUIRED libssh>=0.6.0)
pkg_check_modules (KSBA REQUIRED ksba>=1.0.7)
pkg_check_modules (GPGME REQUIRED gpgme>=1.0.7)

message (STATUS "Looking for libgcrypt...")
find_library (GCRYPT gcrypt)
if (NOT GCRYPT)
  message (SEND_ERROR "The libgcrypt library is required.")
else (NOT GCRYPT)
  message (STATUS "Looking for libgcrypt... ${GCRYPT}")
  execute_process (COMMAND libgcrypt-config --libs
    OUTPUT_VARIABLE GCRYPT_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND libgcrypt-config --cflags
    OUTPUT_VARIABLE GCRYPT_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND libgcrypt-config --version
    OUTPUT_VARIABLE GCRYPT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  message (STATUS "  found libgcrypt, version ${GCRYPT_VERSION}")
  if (GCRYPT_VERSION VERSION_LESS "1.6")
    message (SEND_ERROR "libgcrypt 1.6 or greater is required")
  endif (GCRYPT_VERSION VERSION_LESS "1.6")
  string(REPLACE "-I" "" GCRYPT_INCLUDE_DIRS "${GCRYPT_CFLAGS}")
endif (NOT GCRYPT)

message (STATUS "Looking for pcap...")
find_library (PCAP pcap)
message (STATUS "Looking for pcap... ${PCAP}")
if (NOT PCAP)
  message (SEND_ERROR "The pcap library is required.")
endif (NOT PCAP)

message (STATUS "Looking for pcap-config...")
find_program (PCAP_CONFIG pcap-config)

if (PCAP_CONFIG)
  message (STATUS "Looking for pcap-config... ${PCAP_CONFIG}")
  execute_process (COMMAND pcap-config --libs
    OUTPUT_VARIABLE PCAP_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND pcap-config --cflags
    OUTPUT_VARIABLE PCAP_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
else (PCAP_CONFIG)
  message (STATUS "pcap-config not found, using defaults...")
  set (PCAP_LDFLAGS "-L/usr/lib -lpcap")
  set (PCAP_CFLAGS "-I/usr/include")
endif (PCAP_CONFIG)

find_package (Threads)

set(CSRC "../nasl/")
set (FILES ${CSRC}arc4.c ${CSRC}capture_packet.c ${CSRC}charcnv.c ${CSRC}exec.c ${CSRC}genrand.c ${CSRC}hmacmd5.c
${CSRC}iconv.c ${CSRC}lint.c ${CSRC}md4.c ${CSRC}md5.c ${CSRC}nasl_builtin_find_service.c
${CSRC}nasl_builtin_openvas_tcp_scanner.c ${CSRC}nasl_builtin_synscan.c
${CSRC}nasl_cmd_exec.c ${CSRC}nasl_crypto2.c ${CSRC}nasl_snmp.c ${CSRC}nasl_ssh.c ${CSRC}nasl_cert.c
${CSRC}nasl_crypto.c ${CSRC}nasl_debug.c ${CSRC}nasl_func.c ${CSRC}nasl_grammar.tab.c ${CSRC}nasl_host.c
${CSRC}nasl_http.c ${CSRC}nasl_init.c ${CSRC}nasl_lex_ctxt.c ${CSRC}nasl_misc_funcs.c ${CSRC}nasl_scanner_glue.c
${CSRC}nasl_packet_forgery.c ${CSRC}nasl_packet_forgery_v6.c ${CSRC}nasl_signature.c ${CSRC}nasl_smb.c
${CSRC}nasl_socket.c ${CSRC}nasl_text_utils.c ${CSRC}nasl_tree.c ${CSRC}nasl_var.c ${CSRC}nasl_wmi.c
${CSRC}nasl_isotime.c ${CSRC}ntlmssp.c ${CSRC}smb_crypt.c ${CSRC}smb_crypt2.c ${CSRC}smb_signing.c ${CSRC}time.c ${CSRC}nasl_glonal_ctxt.c ${CSRC}vfsreader.c)


if (NOT OPENVAS_WMICLIENT_FOUND)
  set (FILES ${CSRC}smb_interface_stub.c ${CSRC}wmi_interface_stub.c ${FILES})
endif (NOT OPENVAS_WMICLIENT_FOUND)

if (NOT OPENVAS_WINCMD_FOUND)
  set (FILES ${CSRC}smb_interface_stub.c ${FILES})
endif (NOT OPENVAS_WINCMD_FOUND)

if (KSBA)
  add_definitions (-DHAVE_LIBKSBA)
endif (KSBA)

if (OPENVAS_CONF)
  add_definitions (-DOPENVAS_CONF="${OPENVAS_CONF}")
endif (OPENVAS_CONF)

set_source_files_properties (nasl_grammar.tab.c GENERATED)

## Pass-throughs
add_definitions (-DOPENVAS_STATE_DIR="${OPENVAS_STATE_DIR}")
add_definitions (-DOPENVASLIB_VERSION="${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
add_definitions (-DOPENVAS_SYSCONF_DIR="${OPENVAS_SYSCONF_DIR}")
add_definitions (-DOPENVAS_NASL_VERSION="${PROJECT_VERSION_STRING}")
add_definitions (-DOPENVAS_GPG_BASE_DIR="${OPENVAS_GPG_BASE_DIR}")
add_definitions (-DUSE_VFS)

add_executable (openvas attack.c hosts.c
                main.c nasl_plugins.c openvas.c
                pluginlaunch.c pluginload.c
                pluginscheduler.c plugs_req.c
                processes.c sighand.c utils.c ${FILES})

set_target_properties (openvas PROPERTIES LINKER_LANGUAGE C)

include_directories (${GLIB_INCLUDE_DIRS} ${LIBOPENVAS_NASL_INCLUDE_DIRS}
                     ${LIBGVM_BASE_INCLUDE_DIRS}
                     ${LIBOPENVAS_MISC_INCLUDE_DIRS}
                     ${GCRYPT_INCLUDE_DIRS})

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  # If we got GIT_REVISION at configure time,
  # assume we can get it at build time as well
  if (GIT_REVISION)
    # a custom target that is always built
    add_custom_target (revisiontag ALL)

    # creates gitversion.h using cmake script
    add_custom_command (TARGET revisiontag COMMAND ${CMAKE_COMMAND}
                        -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
                        -P ${CMAKE_SOURCE_DIR}/cmake/GetGit.cmake)

    # explicitly say that the executable depends on custom target
    add_dependencies (openvas revisiontag)

    # include the output directory, where the gitversion.h file is generated
    include_directories (${CMAKE_CURRENT_BINARY_DIR})
    add_definitions (-DGIT_REV_AVAILABLE)
  endif (GIT_REVISION)
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror -Wextra")

if (OPENVAS_VERSION)
  add_definitions (-DOPENVAS_VERSION="${OPENVAS_VERSION}")
endif (OPENVAS_VERSION)

if (GIT_REVISION)
  add_definitions (-DOPENVAS_GIT_REVISION="${GIT_REVISION}")
endif (GIT_REVISION)

add_definitions (-DPREFIX="${CMAKE_INSTALL_PREFIX}")

if (OPENVAS_NVT_DIR)
  add_definitions (-DOPENVAS_NVT_DIR="${OPENVAS_NVT_DIR}")
endif (OPENVAS_NVT_DIR)

if (OPENVAS_CONF)
  add_definitions (-DOPENVAS_CONF="${OPENVAS_CONF}")
endif (OPENVAS_CONF)

if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR="${OPENVAS_STATE_DIR}")
endif (OPENVAS_STATE_DIR)

if (OPENVAS_RUN_DIR)
  add_definitions (-DOPENVAS_RUN_DIR="${OPENVAS_RUN_DIR}")
endif (OPENVAS_RUN_DIR)

if (SYSCONFDIR)
  add_definitions (-DSYSCONFDIR="${SYSCONFDIR}")
endif (SYSCONFDIR)

if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DOPENVAS_SYSCONF_DIR="${OPENVAS_SYSCONF_DIR}")
endif (OPENVAS_SYSCONF_DIR)

if (OPENVAS_DATA_DIR)
  add_definitions (-DOPENVAS_DATA_DIR="${OPENVAS_DATA_DIR}")
endif (OPENVAS_DATA_DIR)

if (NVT_TIMEOUT)
  add_definitions (-DNVT_TIMEOUT=${NVT_TIMEOUT})
endif (NVT_TIMEOUT)

if (SCANNER_NVT_TIMEOUT)
  add_definitions (-DSCANNER_NVT_TIMEOUT=${SCANNER_NVT_TIMEOUT})
endif (SCANNER_NVT_TIMEOUT)

if (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  set (EXECINFO_LDFLAGS "execinfo")
endif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")

target_link_libraries (openvas openvas_misc 
                      ${LIBOPENVAS_NASL_LDFLAGS}
                       ${LIBOPENVAS_MISC_LDFLAGS}
                       ${LIBGVM_BASE_LDFLAGS}
                       ${LIBGVM_BOREAS_LDFLAGS}
                       ${LIBNET_LDFLAGS}
                       ${GLIB_LDFLAGS}
                        ${GCRYPT_LDFLAGS} ${GPGME_LDFLAGS} m
                        ${LIBGVM_BASE_LDFLAGS}
                        ${LIBGVM_UTIL_LDFLAGS}
                        ${REDIS_LDFLAGS}
                        ${ZLIB_LDFLAGS}
                        ${GIO_LDFLAGS}
                        ${OPENVAS_WMICLIENT_LDFLAGS} 
                        ${OPENVAS_WINCMD_LDFLAGS}
                        ${PCAP_LDFLAGS}
                        ${KSBA_LDFLAGS}
                        ${SNMP_LDFLAGS}
                        ${LINKER_HARDENING_FLAGS}
                        ${GNUTLS_LDFLAGS} 
                        ${LIBSSH_LDFLAGS}
                       ${GLIB_LDFLAGS} ${GCRYPT_LDFLAGS}
                       ${EXECINFO_LDFLAGS} ${PCAP_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT})

## Tests

add_executable (attack-test
                EXCLUDE_FROM_ALL
                attack_tests.c
                hosts.c nasl_plugins.c openvas.c
                pluginlaunch.c pluginload.c
                pluginscheduler.c plugs_req.c
                processes.c sighand.c utils.c)

set_target_properties (attack-test PROPERTIES LINKER_LANGUAGE C)

add_test (attack-test attack-test)

target_link_libraries (attack-test openvas_nasl_shared cgreen
                       ${LIBOPENVAS_NASL_LDFLAGS}
                       ${LIBOPENVAS_MISC_LDFLAGS}
                       ${LIBGVM_BASE_LDFLAGS}
                       ${LIBGVM_BOREAS_LDFLAGS}
                       ${GLIB_LDFLAGS} ${GCRYPT_LDFLAGS}
                       ${EXECINFO_LDFLAGS} ${PCAP_LDFLAGS}
                       ${LINKER_HARDENING_FLAGS} ${CMAKE_THREAD_LIBS_INIT}
                       -Wl,--wrap=redis_push_str)

## Static analysis

add_custom_target (cppcheck COMMENT "Running cppcheck..."
                   COMMAND sh -c \"cppcheck ${CMAKE_CURRENT_SOURCE_DIR}\")

add_custom_target (check COMMENT "Checking code...")
add_dependencies (check cppcheck)

## Tag files

set (C_FILES "attack.c" "hosts.c"
     "nasl_plugins.c" "openvas.c"
     "pluginlaunch.c" "pluginload.c"
     "pluginscheduler.c" "plugs_req.c"
     "processes.c" "sighand.c" "utils.c")
add_custom_target (etags COMMENT "Building TAGS..."
                   COMMAND etags ${C_FILES})
add_custom_target (ctags COMMENT "Building tags..."
                   COMMAND ctags ${C_FILES})
add_custom_target (tags COMMENT "Building tags files...")
add_dependencies (tags etags ctags)

## Install

install (TARGETS openvas
         RUNTIME DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
         GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/src/openvas_log.conf
         DESTINATION ${OPENVAS_SYSCONF_DIR})

install (FILES ${CMAKE_BINARY_DIR}/tools/greenbone-nvt-sync
         DESTINATION ${BINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/doc/openvas.8
         DESTINATION ${DATADIR}/man/man8 )


install (FILES ${CMAKE_SOURCE_DIR}/doc/greenbone-nvt-sync.8
         DESTINATION ${DATADIR}/man/man8 )

install (DIRECTORY DESTINATION ${OPENVAS_NVT_DIR})

## End

