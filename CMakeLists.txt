cmake_minimum_required(VERSION 3.20)
project(hem_guard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(HEM_GUARD_BUILD_TESTS "Build the automated tests" ON)

if(MSVC)
  # Fully static: the zip runs on a PC with no extra Microsoft runtime installed.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  add_compile_options(/W4 /permissive- /utf-8 /EHsc)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ---- hem_guard_core : the engine (no user-interface code in here) ----
add_library(hem_guard_core STATIC
  core/src/util.cpp
  core/src/sha256.cpp
  core/src/rules.cpp
  core/src/walk.cpp
  core/src/throttle.cpp
  core/src/scanner.cpp
  core/src/quarantine.cpp
  core/src/undo_store.cpp
  core/src/cleaner.cpp
  core/src/reports.cpp
  core/src/startup.cpp
  core/src/platform_posix.cpp
  core/src/platform_win.cpp
  core/src/startup_win.cpp)
target_include_directories(hem_guard_core PUBLIC core/include)
target_compile_definitions(hem_guard_core PUBLIC HEM_GUARD_VERSION="${PROJECT_VERSION}")
if(WIN32)
  target_link_libraries(hem_guard_core PUBLIC advapi32 ole32 shell32 wintrust crypt32 uuid)
endif()

# ---- hem_guard_cli : thin command-line tool on top of the engine ----
add_executable(hem_guard_cli cli/main.cpp)
target_link_libraries(hem_guard_cli PRIVATE hem_guard_core)

# ---- hem_guard_gui : the window (Windows only) ----
if(WIN32)
  add_executable(hem_guard_gui WIN32 gui/main_win.cpp)
  target_compile_definitions(hem_guard_gui PRIVATE UNICODE _UNICODE)
  target_link_libraries(hem_guard_gui PRIVATE hem_guard_core comctl32 shell32 ole32 user32 gdi32)
endif()

# ---- tests ----
if(HEM_GUARD_BUILD_TESTS)
  add_executable(hem_guard_tests
    tests/test_main.cpp
    tests/test_basics.cpp
    tests/test_scanner.cpp
    tests/test_quarantine.cpp
    tests/test_cleaner.cpp
    tests/test_reports.cpp
    tests/test_startup.cpp)
  target_link_libraries(hem_guard_tests PRIVATE hem_guard_core)
  target_compile_definitions(hem_guard_tests PRIVATE HEM_GUARD_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
endif()
