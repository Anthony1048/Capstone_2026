cmake_minimum_required(VERSION 4.0)
project(Capstone)


set(CMAKE_CXX_STANDARD 20)

add_executable(Capstone
        bbapp.cpp)
target_include_directories(Capstone PRIVATE ${CMAKE_SOURCE_DIR})

# Added to target windows 10 or newer OS
target_compile_definitions(Capstone PRIVATE _WIN32_WINNT=0x0A00)

target_link_libraries(Capstone PRIVATE ws2_32)
target_link_options(Capstone PRIVATE -static -static-libgcc -static-libstdc++)

# After each build, copy supporting folders into the build directory
add_custom_command(TARGET Capstone POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/python
        ${CMAKE_BINARY_DIR}/python
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/html
        ${CMAKE_BINARY_DIR}/html
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/powershell
        ${CMAKE_BINARY_DIR}/powershell
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${CMAKE_BINARY_DIR}/generated reports"
)
