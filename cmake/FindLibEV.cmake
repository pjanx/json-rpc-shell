# Public Domain

# The author of libev is a dick and doesn't want to add support for pkg-config,
# forcing us to include this pointless file in the distribution.

# Some distributions do add it, though
find_package (PkgConfig REQUIRED)
pkg_check_modules (LibEV QUIET libev)

set (required_vars LibEV_LIBRARIES)
if (NOT LibEV_FOUND)
	find_path (LibEV_INCLUDE_DIRS ev.h)
	find_library (LibEV_LIBRARIES NAMES ev)
	list (APPEND required_vars LibEV_INCLUDE_DIRS)
endif ()

include (FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS (LibEV DEFAULT_MSG ${required_vars})

mark_as_advanced (LibEV_LIBRARIES LibEV_INCLUDE_DIRS)
