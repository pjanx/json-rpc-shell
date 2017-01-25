project (json-rpc-shell C)
cmake_minimum_required (VERSION 2.8.5)

# Options
option (WANT_READLINE "Use GNU Readline for the UI (better)" ON)
option (WANT_LIBEDIT "Use BSD libedit for the UI" OFF)

# Moar warnings
if ("${CMAKE_C_COMPILER_ID}" MATCHES "GNU" OR CMAKE_COMPILER_IS_GNUC)
	# -Wunused-function is pretty annoying here, as everything is static
	set (CMAKE_C_FLAGS
		"${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -Wno-unused-function")
endif ("${CMAKE_C_COMPILER_ID}" MATCHES "GNU" OR CMAKE_COMPILER_IS_GNUC)

# Version
set (project_VERSION_MAJOR "0")
set (project_VERSION_MINOR "1")
set (project_VERSION_PATCH "0")

set (project_VERSION "${project_VERSION_MAJOR}")
set (project_VERSION "${project_VERSION}.${project_VERSION_MINOR}")
set (project_VERSION "${project_VERSION}.${project_VERSION_PATCH}")

# For custom modules
set (CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

# Dependencies
find_package (Curses)
find_package (PkgConfig REQUIRED)
pkg_check_modules (dependencies REQUIRED libcurl jansson)
pkg_check_modules (libssl REQUIRED libssl libcrypto)
find_package (LibEV REQUIRED)
pkg_check_modules (ncursesw ncursesw)

set (project_libraries ${dependencies_LIBRARIES}
	${libssl_LIBRARIES} ${LIBEV_LIBRARIES})
include_directories (${dependencies_INCLUDE_DIRS}
	${libssl_INCLUDE_DIRS} ${LIBEV_INCLUDE_DIRS})

if (ncursesw_FOUND)
	list (APPEND project_libraries ${ncursesw_LIBRARIES})
	include_directories (${ncursesw_INCLUDE_DIRS})
elseif (CURSES_FOUND)
	list (APPEND project_libraries ${CURSES_LIBRARY})
	include_directories (${CURSES_INCLUDE_DIR})
else (CURSES_FOUND)
	message (SEND_ERROR "Curses not found")
endif (ncursesw_FOUND)

if ((WANT_READLINE AND WANT_LIBEDIT) OR (NOT WANT_READLINE AND NOT WANT_LIBEDIT))
	message (SEND_ERROR "You have to choose either GNU Readline or libedit")
elseif (WANT_READLINE)
	list (APPEND project_libraries readline)
elseif (WANT_LIBEDIT)
	pkg_check_modules (libedit REQUIRED libedit)
	list (APPEND project_libraries ${libedit_LIBRARIES})
	include_directories (${libedit_INCLUDE_DIRS})
endif ((WANT_READLINE AND WANT_LIBEDIT) OR (NOT WANT_READLINE AND NOT WANT_LIBEDIT))

# Generate a configuration file
set (HAVE_READLINE "${WANT_READLINE}")
set (HAVE_EDITLINE "${WANT_LIBEDIT}")

configure_file (${PROJECT_SOURCE_DIR}/config.h.in ${PROJECT_BINARY_DIR}/config.h)
include_directories (${PROJECT_BINARY_DIR})

# Build the main executable and link it
add_executable (${PROJECT_NAME} ${PROJECT_NAME}.c http-parser/http_parser.c)
target_link_libraries (${PROJECT_NAME} ${project_libraries})

# The files to be installed
include (GNUInstallDirs)
install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (PROGRAMS json-format.pl DESTINATION ${CMAKE_INSTALL_BINDIR})
install (FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})

# Generate documentation from program help
find_program (HELP2MAN_EXECUTABLE help2man)
if (NOT HELP2MAN_EXECUTABLE)
	message (FATAL_ERROR "help2man not found")
endif (NOT HELP2MAN_EXECUTABLE)

foreach (page ${PROJECT_NAME})
	set (page_output "${PROJECT_BINARY_DIR}/${page}.1")
	list (APPEND project_MAN_PAGES "${page_output}")
	add_custom_command (OUTPUT ${page_output}
		COMMAND ${HELP2MAN_EXECUTABLE} -N
			"${PROJECT_BINARY_DIR}/${page}" -o ${page_output}
		DEPENDS ${page}
		COMMENT "Generating man page for ${page}" VERBATIM)
endforeach (page)

add_custom_target (docs ALL DEPENDS ${project_MAN_PAGES})

foreach (page ${project_MAN_PAGES})
	string (REGEX MATCH "\\.([0-9])$" manpage_suffix "${page}")
	install (FILES "${page}"
		DESTINATION "${CMAKE_INSTALL_MANDIR}/man${CMAKE_MATCH_1}")
endforeach (page)

# CPack
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "Shell for running JSON-RPC 2.0 queries")
set (CPACK_PACKAGE_VENDOR "Premysl Janouch")
set (CPACK_PACKAGE_CONTACT "Přemysl Janouch <p.janouch@gmail.com>")
set (CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set (CPACK_PACKAGE_VERSION_MAJOR ${project_VERSION_MAJOR})
set (CPACK_PACKAGE_VERSION_MINOR ${project_VERSION_MINOR})
set (CPACK_PACKAGE_VERSION_PATCH ${project_VERSION_PATCH})
set (CPACK_GENERATOR "TGZ;ZIP")
set (CPACK_PACKAGE_FILE_NAME
	"${PROJECT_NAME}-${project_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set (CPACK_PACKAGE_INSTALL_DIRECTORY "${PROJECT_NAME}-${project_VERSION}")
set (CPACK_SOURCE_GENERATOR "TGZ;ZIP")
set (CPACK_SOURCE_IGNORE_FILES "/\\\\.git;/build;/CMakeLists.txt.user")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${project_VERSION}")

include (CPack)
