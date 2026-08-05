cmake_minimum_required(VERSION 3.16)
project(crossclip-sync LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Network)
find_package(OpenSSL REQUIRED)

add_executable(server
    server.cpp
    crypto.cpp
)
target_link_libraries(server PRIVATE
    Qt6::Core Qt6::Network
    OpenSSL::Crypto
)

add_executable(client
    client.cpp
    crypto.cpp
)
target_link_libraries(client PRIVATE
    Qt6::Core Qt6::Gui Qt6::Network
    OpenSSL::Crypto
)
