cmake_minimum_required(VERSION 2.6)
project(stx)

add_definitions(-D_GNU_SOURCE)

add_executable(test-cares-st test-cares-st.c cares-st.c)
target_link_libraries(test-cares-st glib-2.0 st cares)

add_executable(st-ssl ssl.c cares-st.c bio_netfd.c)
target_link_libraries(st-ssl glib-2.0 st cares ssl)
add_dependencies(st-ssl st cares)

