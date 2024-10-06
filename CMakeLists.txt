# The SEL extension library
# Free software published under the MIT license.

cmake_minimum_required(VERSION 3.24)

project(sel_uri LANGUAGES CXX)
option(SEL_URI_TESTS "Build unit tests for this project" OFF)

set(CMAKE_CXX_STANDARD 17)

add_library(sel_uri STATIC)
target_include_directories(sel_uri PUBLIC "include")
target_sources(sel_uri PRIVATE "source/uri.re.cpp")
add_library(sel::uri ALIAS sel_uri)

include(CTest)
if(BUILD_TESTING AND SEL_URI_TESTS)
  set(CMAKE_CXX_STANDARD 20)

  include("cmake/get_doctest.cmake")
  get_doctest()

  add_executable(sel_uri_tests "test/uri_tests.cpp" "test/main.cpp")
  target_compile_definitions(sel_uri_tests PRIVATE "DOCTEST_CONFIG_USE_STD_HEADERS=1")
  target_compile_definitions(sel_uri_tests PRIVATE "DOCTEST_CONFIG_SUPER_FAST_ASSERTS=1")
  target_link_libraries(sel_uri_tests PRIVATE sel_uri doctest::doctest)

  include(doctest)
  doctest_discover_tests(sel_uri_tests)
endif()
