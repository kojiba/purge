cmake_minimum_required(VERSION 3.2)
project(purge)

set(SOURCE_FILES purge.c purge.h
                 evasion.h evasion.c

                 main.c)

add_executable(purge ${SOURCE_FILES} )