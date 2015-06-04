cmake_minimum_required(VERSION 3.2)
project(purge)

set(SOURCE_FILES purge.h   purge.c
                 evasion.h evasion.c
                 PurgeEvasionUtils.h PurgeEvasionUtils.c
                 main.c)

add_executable(purge ${SOURCE_FILES} )