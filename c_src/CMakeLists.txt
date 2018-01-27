# Copyright 2017 Xaptum, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License

cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ecdaa-erlang
        LANGUAGES C
        VERSION "0.0.1")

include(GNUInstallDirs)
include(CTest)

set(ECDAA_NIF_VERSION ${PROJECT_VERSION})
set(ECDAA_NIF_SOVERSION ${PROJECT_VERSION_MAJOR})

list(APPEND CMAKE_MODULE_PATH CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

#SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wextra -std=c99 -Wno-missing-field-initializers")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -std=c99 -Wno-missing-field-initializers")

SET(CMAKE_C_FLAGS_DEBUGWITHCOVERAGE "${CMAKE_C_FLAGS_DEBUGWITHCOVERAGE} -O0 -fprofile-arcs -ftest-coverage")

SET(CMAKE_C_FLAGS_RELWITHSANITIZE "${CMAKE_C_FLAGS_RELWITHSANITIZE} -O2 -g -fsanitize=address,undefined -fsanitize=unsigned-integer-overflow")

# The following options are automatically passed to the `memcheck` executable:
# `--error-exitcode=5` A memory error causes a return code of 5, so memory errors will fail the tests.
# `--leak-check=full` Search for memory leaks after program completion, and give a full report for each individually.
#   - As we're striving for "malloc-free" code, we expect to have zero memory leaks
# `-v` Verbose `memcheck` output
# `--track-origins=yes` Track the origin of uninitialized values (small Valgrind performance hit)
# `--partial-loads-ok=no` Loads from partially invalid addresses are treated the same as loads from completely invalid addresses
find_program(MEMORYCHECK_COMMAND NAMES valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS
        "--error-exitcode=5 --leak-check=full -v --track-origins=yes --partial-loads-ok=no")

# set erl_interface lib variables
execute_process(COMMAND erl -noshell -s init stop -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)])." OUTPUT_VARIABLE ERTS_INCLUDE_DIR)
MESSAGE( STATUS "ERTS_INCLUDE_DIR:         " ${ERTS_INCLUDE_DIR} )

execute_process(COMMAND erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, include)])." OUTPUT_VARIABLE ERL_INTERFACE_INCLUDE_DIR)
MESSAGE( STATUS "ERL_INTERFACE_INCLUDE_DIR:         " ${ERL_INTERFACE_INCLUDE_DIR} )

execute_process(COMMAND erl -noshell -s init stop -eval "io:format(\"~s\", [code:lib_dir(erl_interface, lib)])." OUTPUT_VARIABLE ERL_INTERFACE_LIB_DIR)
MESSAGE( STATUS "ERL_INTERFACE_LIB_DIR:         " ${ERL_INTERFACE_LIB_DIR} )


################################################################################
# Add shared Libary
################################################################################

add_subdirectory(ecdaa)

link_directories(${ERL_INTERFACE_LIB_DIR})

add_library(ecdaa-erlang SHARED ecdaa.c)

set_target_properties(ecdaa-erlang PROPERTIES
    VERSION "${ECDAA_NIF_VERSION}"
    SOVERSION "${ECDAA_NIF_SOVERSION}"
)

target_link_libraries(ecdaa-erlang
PUBLIC erl_interface ei)

target_include_directories(ecdaa-erlang PUBLIC
    $<BUILD_INTERFACE:${ERL_INTERFACE_INCLUDE_DIR}>
    $<BUILD_INTERFACE:${ERTS_INCLUDE_DIR}>
    #$<BUILD_INTERFACE:${ECDAA_INCLUDE_DIRS}>
    #$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

install(TARGETS ecdaa-erlang
    EXPORT ${CMAKE_PROJECT_NAME}Targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

################################################################################
# CMake export
################################################################################
install(EXPORT ${CMAKE_PROJECT_NAME}Targets
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${CMAKE_PROJECT_NAME}
        FILE        ${CMAKE_PROJECT_NAME}Config.cmake
)
