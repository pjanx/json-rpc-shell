project (json-rpc-shell C)
cmake_minimum_required (VERSION 2.8.5)

# Moar warnings
if ("${CMAKE_C_COMPILER_ID}" MATCHES "GNU" OR CMAKE_COMPILER_IS_GNUC)
	set (CMAKE_C_FLAGS "-std=c99")
	set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -Wextra")
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
find_package (PkgConfig REQUIRED)
pkg_check_modules (dependencies REQUIRED libcurl jansson)
find_package (LibEV REQUIRED)

include_directories (${dependencies_INCLUDE_DIRS} ${LIBEV_INCLUDE_DIRS})

# Build the main executable and link it
add_executable (${PROJECT_NAME} ${PROJECT_NAME}.c)
target_link_libraries (${PROJECT_NAME}
	${dependencies_LIBRARIES} ${LIBEV_LIBRARIES} readline)

# The files to be installed
include (GNUInstallDirs)
install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
install (FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})

# CPack
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "Shell for JSON-RPC 2.0 HTTP queries")
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

