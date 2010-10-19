project(st-1.9)

cmake_minimum_required(VERSION 2.6)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif(NOT CMAKE_BUILD_TYPE)

set(CMAKE_C_FLAGS_DEBUG "-DDEBUG -g3 -ggdb")

set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -fPIC -std=gnu99 -pedantic -pthread -Wall -Wpointer-arith -Wno-format-y2k -Wstrict-prototypes -Wmissing-declarations -Wnested-externs -Wextra -Wundef -Wwrite-strings -Wold-style-definition -Wno-missing-field-initializers -Wredundant-decls -Wno-unused-parameter -Wno-sign-compare -Wmissing-prototypes")

add_definitions(-DMD_HAVE_EPOLL -DLINUX)

# check for valgrind. this should really be in FindValgrind.cmake
# http://www.itk.org/Wiki/CMake:How_To_Find_Installed_Software
find_file(VALGRIND_H valgrind.h /usr/include/valgrind /usr/local/include/valgrind)
message("valgrind headers: ${VALGRIND_H}")
if(NOT VALGRIND_H)
# this will remove valgrind stack tracking support from state-threads
add_definitions(-DNVALGRIND)
endif(NOT VALGRIND_H)

exec_program(${CMAKE_COMMAND} ARGS -E copy ${CMAKE_CURRENT_SOURCE_DIR}/public.h ${CMAKE_CURRENT_BINARY_DIR}/st.h)
# use gcc for the asm file because it needs to be
# pre-processed by cpp first
SET_SOURCE_FILES_PROPERTIES(md.S PROPERTIES LANGUAGE C)
add_library(st STATIC md.S event.c io.c  key.c  sched.c  stk.c  sync.c)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
#add_executable(server examples/server.c examples/error.c)
#target_link_libraries(server st)

add_executable(lookupdns examples/lookupdns.c examples/res.c)
target_link_libraries(lookupdns st resolv)
