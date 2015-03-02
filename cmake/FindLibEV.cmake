# Public Domain

# The author of libev is a dick and doesn't want to add support for pkg-config,
# forcing us to include this pointless file in the distribution.

# Some distributions do add it, though
find_package (PkgConfig REQUIRED)
pkg_check_modules (LIBEV QUIET libev)

if (NOT LIBEV_FOUND)
	find_path (LIBEV_INCLUDE_DIRS ev.h)
	find_library (LIBEV_LIBRARIES NAMES ev)

	if (LIBEV_INCLUDE_DIRS AND LIBEV_LIBRARIES)
		set (LIBEV_FOUND TRUE)
	endif (LIBEV_INCLUDE_DIRS AND LIBEV_LIBRARIES)
endif (NOT LIBEV_FOUND)

