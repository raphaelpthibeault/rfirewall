add_compile_options(-g -O2 -target bpf -D__TARGET_ARCH_x86)

add_library(read OBJECT
	read.bpf.c
)
target_include_directories(read PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_command(OUTPUT combined_bpf_lib.o
	COMMAND bpftool gen object combined_bpf_lib.o $<TARGET_OBJECTS:read>
	DEPENDS read
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

