cmake_minimum_required(VERSION 3.16)
project(coruscant-lb C)

# ── BPF object (Linux only, requires clang + BPF target) ─────────────────────
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(CLANG clang REQUIRED)

    add_custom_command(
        OUTPUT  ${CMAKE_SOURCE_DIR}/src/xdp_lb.o
        COMMAND ${CLANG}
                -O2 -g -Wall
                -target bpf
                -D__TARGET_ARCH_x86_64
                -I/usr/include/
                -I/usr/include/x86_64-linux-gnu
                -c ${CMAKE_SOURCE_DIR}/src/xdp_lb.c
                -o ${CMAKE_SOURCE_DIR}/src/xdp_lb.o
        DEPENDS ${CMAKE_SOURCE_DIR}/src/xdp_lb.c
        COMMENT "Compiling XDP eBPF program"
    )

    add_custom_target(xdp_lb ALL
        DEPENDS ${CMAKE_SOURCE_DIR}/src/xdp_lb.o
    )
endif()

# ── Unit tests (portable: macOS + Linux) ─────────────────────────────────────
add_executable(test_xdp_lb tests/test_xdp_lb.c)
target_compile_options(test_xdp_lb PRIVATE -O2 -g -Wall -Wextra)

enable_testing()
add_test(NAME xdp_lb COMMAND test_xdp_lb)
