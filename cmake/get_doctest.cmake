# The SEL extension library
# Free software published under the MIT license.

include(FetchContent)

function(get_doctest)
  if(TARGET doctest::doctest)
    return()
  endif()

  find_package(doctest CONFIG)
  if(NOT doctest_FOUND)
    FetchContent_Declare(doctest
      URL "https://github.com/doctest/doctest/archive/refs/tags/v2.4.11.tar.gz"
      URL_HASH "SHA256=632ed2c05a7f53fa961381497bf8069093f0d6628c5f26286161fbd32a560186")
    FetchContent_MakeAvailable(doctest)
    list(APPEND CMAKE_MODULE_PATH "${doctest_SOURCE_DIR}/scripts/cmake")
  endif()

  set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" PARENT_SCOPE)
endfunction()
