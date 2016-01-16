# Public Domain

find_library (LIBMAGIC_LIBRARIES magic)
find_path (LIBMAGIC_INCLUDE_DIRS magic.h)

include (FindPackageHandleStandardArgs)
find_package_handle_standard_args (LibMagic DEFAULT_MSG
	LIBMAGIC_LIBRARIES LIBMAGIC_INCLUDE_DIRS)

mark_as_advanced (LIBMAGIC_LIBRARIES LIBMAGIC_INCLUDE_DIRS)
