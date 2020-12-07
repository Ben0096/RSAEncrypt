
cmake_minimum_required(VERSION 2.8)

set(SOURCES
	RSA_run.cpp
	)

set(HEADERS
	)

project("RSAEncrypt")

add_executable(rsa ${SOURCES} ${HEADERS})
target_include_directories(rsa PRIVATE include)
