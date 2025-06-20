cmake_minimum_required(VERSION 4.0.1)
project(rfirewall
	DESCRIPTION "Linux userspace application-level firewall"
	LANGUAGES C
)

set(CMAKE_C_COMPILER "clang-18")
set(CMAKE_C_STANDARD 23)

add_compile_options(-Wall -Wextra)

find_package(PkgConfig REQUIRED)

add_subdirectory(rfirewall)

