cmake_minimum_required(VERSION 3.14)
project(wpcap_test)

set(CMAKE_CXX_STANDARD 14)

add_definitions(-DNPCAP_ROOT)

include_directories(${NPCAP_ROOT}/Include)

add_executable(wpcap_test main.cpp network_addr.h packet.h)
target_link_libraries(wpcap_test wsock32 ${NPCAP_ROOT}/Lib/x64/wpcap.lib)