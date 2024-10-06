# The SEL extension library
# Free software published under the MIT license.

find_program(RE2C_PROGRAM "re2c" REQUIRED)

function(generate_re2c input suffix)
  if(NOT suffix)
    message(FATAL_ERROR "No suffix given")
  endif()
  if("${input}" IS_NEWER_THAN "${input}${suffix}")
    message(STATUS "Generating: ${input}${suffix}")
    execute_process(
      COMMAND "${RE2C_PROGRAM}" "--no-generation-date"
        "-o" "${input}${suffix}" "${input}"
      COMMAND_ERROR_IS_FATAL ANY)
  else()
    message(STATUS "Up-to-date: ${input}${suffix}")
  endif()
endfunction()
