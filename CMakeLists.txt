cmake_minimum_required (VERSION 3.0)
project (json-rpc-shell VERSION 1.1.0 LANGUAGES C)

# Options
option (WANT_READLINE "Use GNU Readline for the UI (better)" ON)
option (WANT_LIBEDIT "Use BSD libedit for the UI" OFF)

# Moar warnings
if ("${CMAKE_C_COMPILER_ID}" MATCHES "GNU" OR CMAKE_COMPILER_IS_GNUCC)
	# -Wunused-function is pretty annoying here, as everything is static
	set (CMAKE_C_FLAGS
		"${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -Wno-unused-function")
endif ()

# For custom modules
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

# Dependencies
find_package (Curses)
find_package (PkgConfig REQUIRED)
pkg_check_modules (dependencies REQUIRED libcurl jansson)
# Note that cURL can link to a different version of libssl than we do,
# in which case the results are undefined
pkg_check_modules (libssl REQUIRED libssl libcrypto)
find_package (LibEV REQUIRED)
pkg_check_modules (ncursesw ncursesw)

set (project_libraries ${dependencies_LIBRARIES}
	${libssl_LIBRARIES} ${LIBEV_LIBRARIES})
include_directories (${dependencies_INCLUDE_DIRS}
	${libssl_INCLUDE_DIRS} ${LIBEV_INCLUDE_DIRS})

# -liconv may or may not be a part of libc
find_library (iconv_LIBRARIES iconv)
if (iconv_LIBRARIES)
	list (APPEND project_libraries ${iconv_LIBRARIES})
endif ()

if ("${CMAKE_SYSTEM_NAME}" MATCHES "BSD")
	# Need this for SIGWINCH in FreeBSD and OpenBSD respectively;
	# our POSIX version macros make it undefined
	add_definitions (-D__BSD_VISIBLE=1 -D_BSD_SOURCE=1)
endif ()

if (ncursesw_FOUND)
	list (APPEND project_libraries ${ncursesw_LIBRARIES})
	include_directories (${ncursesw_INCLUDE_DIRS})
elseif (CURSES_FOUND)
	list (APPEND project_libraries ${CURSES_LIBRARY})
	include_directories (${CURSES_INCLUDE_DIR})
else ()
	message (SEND_ERROR "Curses not found")
endif ()

if ((WANT_READLINE AND WANT_LIBEDIT) OR (NOT WANT_READLINE AND NOT WANT_LIBEDIT))
	message (SEND_ERROR "You have to choose either GNU Readline or libedit")
elseif (WANT_READLINE)
	# OpenBSD's default readline is too old
	if ("${CMAKE_SYSTEM_NAME}" MATCHES "OpenBSD")
		include_directories (${OPENBSD_LOCALBASE}/include/ereadline)
		list (APPEND degesch_libraries ereadline)
	else ()
		list (APPEND degesch_libraries readline)
	endif ()
elseif (WANT_LIBEDIT)
	pkg_check_modules (libedit REQUIRED libedit)
	list (APPEND project_libraries ${libedit_LIBRARIES})
	include_directories (${libedit_INCLUDE_DIRS})
endif ()

# Generate a configuration file
set (HAVE_READLINE "${WANT_READLINE}")
set (HAVE_EDITLINE "${WANT_LIBEDIT}")

configure_file (${PROJECT_SOURCE_DIR}/config.h.in ${PROJECT_BINARY_DIR}/config.h)
include_directories (${PROJECT_BINARY_DIR})

# Build the main executable and link it
add_executable (${PROJECT_NAME} ${PROJECT_NAME}.c http-parser/http_parser.c)
target_link_libraries (${PROJECT_NAME} ${project_libraries})

# Development tools
find_package (LibMagic)
if (LIBMAGIC_FOUND)
	include_directories (${LIBMAGIC_INCLUDE_DIRS})
	add_executable (json-rpc-test-server
		json-rpc-test-server.c http-parser/http_parser.c)
	target_link_libraries (json-rpc-test-server
		${project_libraries} ${LIBMAGIC_LIBRARIES})
endif ()

# The files to be installed
include (GNUInstallDirs)
install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (PROGRAMS json-format.pl DESTINATION ${CMAKE_INSTALL_BINDIR})
install (FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Generate documentation from text markup
find_program (ASCIIDOCTOR_EXECUTABLE asciidoctor)
if (NOT ASCIIDOCTOR_EXECUTABLE)
	message (FATAL_ERROR "asciidoctor not found")
endif ()

foreach (page ${PROJECT_NAME})
	set (page_output "${PROJECT_BINARY_DIR}/${page}.1")
	list (APPEND project_MAN_PAGES "${page_output}")
	add_custom_command (OUTPUT ${page_output}
		COMMAND ${ASCIIDOCTOR_EXECUTABLE} -b manpage
			-a release-version=${PROJECT_VERSION}
			"${PROJECT_SOURCE_DIR}/${page}.adoc"
			-o "${page_output}"
		DEPENDS ${page}.adoc
		COMMENT "Generating man page for ${page}" VERBATIM)
endforeach ()

add_custom_target (docs ALL DEPENDS ${project_MAN_PAGES})

foreach (page ${project_MAN_PAGES})
	string (REGEX MATCH "\\.([0-9])$" manpage_suffix "${page}")
	install (FILES "${page}"
		DESTINATION "${CMAKE_INSTALL_MANDIR}/man${CMAKE_MATCH_1}")
endforeach ()

# CPack
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "A shell for JSON-RPC 2.0")
set (CPACK_PACKAGE_VENDOR "Premysl Eric Janouch")
set (CPACK_PACKAGE_CONTACT "Přemysl Eric Janouch <p@janouch.name>")
set (CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set (CPACK_GENERATOR "TGZ;ZIP")
set (CPACK_PACKAGE_FILE_NAME
	"${PROJECT_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set (CPACK_PACKAGE_INSTALL_DIRECTORY "${PROJECT_NAME}-${PROJECT_VERSION}")
set (CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set (CPACK_SOURCE_IGNORE_FILES "/\\\\.git;/build;/CMakeLists.txt.user")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${PROJECT_VERSION}")

include (CPack)
