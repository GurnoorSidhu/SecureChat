cmake_minimum_required(VERSION 3.16)
project(SecureChat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable AUTOMOC/UIC/RCC for Qt
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Find Qt5 modules
find_package(Qt5 REQUIRED COMPONENTS Widgets Network)

# Try to find Crypto++ library (common names)
find_library(CRYPTOPP_LIB NAMES cryptopp crypto++ libcryptopp)

if (NOT CRYPTOPP_LIB)
    message(WARNING "Crypto++ library not found by find_library(). You may need to install libcrypto++-dev or adjust CMAKE_PREFIX_PATH.")
endif()

add_executable(SecureChat
    main.cpp
    mainwindow.cpp
    mainwindow.h
    cryptohelper.cpp
    cryptohelper.h
)

# Link against Qt5 and Crypto++ (if found)
if (CRYPTOPP_LIB)
    target_link_libraries(SecureChat
        PRIVATE Qt5::Widgets Qt5::Network ${CRYPTOPP_LIB}
    )
else()
    target_link_libraries(SecureChat
        PRIVATE Qt5::Widgets Qt5::Network
    )
endif()

# On some systems you may need to hint CMake where Qt is:
# cmake -DCMAKE_PREFIX_PATH=/path/to/Qt5 ..
