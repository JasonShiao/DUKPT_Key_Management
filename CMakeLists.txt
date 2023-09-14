if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

project(DUKPT VERSION 1.0.0)

add_executable(${PROJECT_NAME})

target_sources(${PROJECT_NAME} PRIVATE
  src/main.c
  src/DES.c
  src/dukpt.c
  src/TDES.c
)

target_include_directories(${PROJECT_NAME} PRIVATE inc)
