cmake_minimum_required(VERSION 3.18)
project(dnsextlang LANGUAGES C VERSION 0.0.1)

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -Wconversion -Wmissing-prototypes)
endif()

add_executable(dnsextlang dnsextlang.c readfile.c mustach.c)
