
cmake_minimum_required(VERSION 2.8)

set(SOURCES
	RSA_enc.cpp
	BigInt.hpp
	)

set(HEADERS
	)

project("RSAEncrypt")

add_executable(rsa ${SOURCES} ${HEADERS})

SET(GCC_COVERAGE_COMPILE_FLAGS "-std=c++11")

add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})

target_include_directories(rsa PRIVATE include)
