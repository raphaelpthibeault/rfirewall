include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
)

add_subdirectory(bpf)

find_package(PkgConfig REQUIRED)
# find_package(LIBBPF REQUIRED) ?
pkg_check_modules(LIBBPF REQUIRED libbpf)

add_executable(rfirewall
	rfirewall.c
)

add_dependencies(rfirewall
	bpf_skeleton
)

target_include_directories(rfirewall SYSTEM PRIVATE
	${CMAKE_BINARY_DIR}/rfirewall # for skeleton
	${LIBBPF_INCLUDE_DIRS}
)

target_link_libraries(rfirewall PRIVATE
	${LIBBPF_LIBRARIES}
)

# target link libraries?
# -lelf, -lz, pthread

target_compile_options(rfirewall PRIVATE
	${LIBBPF_CFLAGS}
)

