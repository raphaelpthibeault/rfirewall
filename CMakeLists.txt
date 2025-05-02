cmake_minimum_required(VERSION 4.0.1)
project(rfirewall
	DESCRIPTION "Linux userspace application-level firewall"
	LANGUAGES C
)

set(CMAKE_C_COMPILER "clang-18")
set(CMAKE_C_STANDARD 23)

# TOOD find package/library for libmnl and netlink/netfilter and all of them, later

add_compile_options(-Wall -Wextra)

add_subdirectory(rfirewall)
