cmake_minimum_required(VERSION 3.16)
project(coruscant-lb C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── BPF object + userspace binaries (Linux only) ─────────────────────────────
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(CLANG clang REQUIRED)

    add_custom_command(
        OUTPUT  ${CMAKE_SOURCE_DIR}/src/xdp_lb.o
        COMMAND ${CLANG}
                -O2 -g -Wall
                -target bpf
                -D__TARGET_ARCH_x86_64
                -I${CMAKE_SOURCE_DIR}/src
                -I/usr/include/
                -I/usr/include/x86_64-linux-gnu
                -c ${CMAKE_SOURCE_DIR}/src/xdp_lb.c
                -o ${CMAKE_SOURCE_DIR}/src/xdp_lb.o
        DEPENDS ${CMAKE_SOURCE_DIR}/src/xdp_lb.c
                ${CMAKE_SOURCE_DIR}/src/lb_common.h
        COMMENT "Compiling XDP eBPF program"
    )

    add_custom_target(xdp_lb ALL
        DEPENDS ${CMAKE_SOURCE_DIR}/src/xdp_lb.o
    )

    find_library(LIBBPF_LIB bpf)
    if(LIBBPF_LIB)
        # lb_ctrl — attach/detach XDP, manage backends map
        add_executable(lb_ctrl src/lb_ctrl.cpp)
        target_include_directories(lb_ctrl PRIVATE src)
        target_compile_options(lb_ctrl PRIVATE -O2 -g -Wall -Wextra)
        target_link_libraries(lb_ctrl PRIVATE ${LIBBPF_LIB} elf z)

        # lb_healthd — background health-checker daemon
        add_executable(lb_healthd src/lb_healthd.cpp)
        target_include_directories(lb_healthd PRIVATE src)
        target_compile_options(lb_healthd PRIVATE -O2 -g -Wall -Wextra)
        target_link_libraries(lb_healthd PRIVATE ${LIBBPF_LIB} elf z)
    else()
        message(WARNING "libbpf not found — lb_ctrl and lb_healthd will not be built (run scripts/install_deps.sh)")
    endif()
endif()

# ── Unit tests (portable: macOS + Linux) ─────────────────────────────────────
add_executable(test_xdp_lb tests/test_xdp_lb.c)
target_include_directories(test_xdp_lb PRIVATE src)
target_compile_options(test_xdp_lb PRIVATE -O2 -g -Wall -Wextra)

enable_testing()
add_test(NAME xdp_lb COMMAND test_xdp_lb)
