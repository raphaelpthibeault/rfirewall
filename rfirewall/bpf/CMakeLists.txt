add_compile_options(-g -O2 -target bpf -D__TARGET_ARCH_x86)

add_library(bpf_files OBJECT
	maps.bpf.h
	tcpconn.bpf.c
)
target_include_directories(bpf_files PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_command(OUTPUT combined_bpf_lib.o
	COMMAND bpftool gen object combined_bpf_lib.o $<TARGET_OBJECTS:bpf_files>
	DEPENDS bpf_files
	COMMAND_EXPAND_LISTS
	VERBATIM
	COMMENT "Generate combined_bpf_lib.o"
)

add_custom_command(OUTPUT bpf-skeleton.h
	COMMAND bpftool gen skeleton combined_bpf_lib.o > bpf-skeleton.h
	DEPENDS combined_bpf_lib.o
	VERBATIM
	COMMENT "Generate bpf-skeleton.h"
)

add_custom_target(bpf_skeleton DEPENDS bpf-skeleton.h)

