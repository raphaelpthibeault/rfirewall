include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	lib/
)

add_subdirectory(bpf)

pkg_check_modules(LIBBPF REQUIRED libbpf)

add_executable(rfirewall_exec
	rfirewall.c
	conn/conn.c
	lib/rradix.c
	conn/packets.c
)

# set the output directory for the executable to build/ (or the running directory)
set_target_properties(rfirewall_exec PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_dependencies(rfirewall_exec
	bpf_skeleton
)

target_include_directories(rfirewall_exec SYSTEM PRIVATE
	${CMAKE_BINARY_DIR}/rfirewall # for skeleton
	${LIBBPF_INCLUDE_DIRS}
)

target_link_libraries(rfirewall_exec PRIVATE
	${LIBBPF_LIBRARIES}
	netfilter_queue
	pthread
	nfnetlink
	mnl
)

target_compile_options(rfirewall_exec PRIVATE
	${LIBBPF_CFLAGS}
)

