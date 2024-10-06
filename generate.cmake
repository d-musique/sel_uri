#!/usr/bin/cmake -P
# The SEL extension library
# Free software published under the MIT license.

include("cmake/generators/re2c.cmake")
generate_re2c("source/uri.re" ".cpp")
