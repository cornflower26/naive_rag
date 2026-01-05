cmake_minimum_required(VERSION 3.30)
project(naive_rag)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Xclang -fopenmp -L/usr/local/Cellar/libomp/21.1.8/lib -I/usr/local/Cellar/libomp/21.1.8/include")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")
set(CMAKE_OSX_ARCHITECTURES "x86_64")

find_package(faiss REQUIRED)
link_libraries(faiss)

#add_subdirectory(/usr/local/Cellar/faiss/1.13.2/include/faiss)

include_directories(/usr/local/Cellar/faiss/1.13.2/include/faiss)
link_directories(/usr/local/Cellar/faiss/1.13.2/lib)



add_executable(naive_rag main.cpp
        include/config.h
        include/client.h
        include/server.h
        include/vector_utils.h
        src/client.cpp
        src/server.cpp
        src/vector_utils.cpp
        utils.cpp)

target_link_libraries(naive_rag faiss)

add_library(openfhecorelib SHARED IMPORTED)
add_library(openfhepkelib SHARED IMPORTED)

set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEpke.so")
set_target_properties(openfhecorelib PROPERTIES IMPORTED_LOCATION "/usr/local/lib/libOPENFHEcore.so")

include_directories("/usr/local/include/openfhe")
include_directories("/usr/local/include/openfhe/core")
include_directories("/usr/local/include/openfhe/pke")
include_directories("/usr/local/include/openfhe/binfhe")

link_directories("/usr/local/lib")
link_directories("/usr/include")

#target_link_libraries(SLAP omp)
target_link_libraries(naive_rag OPENFHEcore)
target_link_libraries(naive_rag OPENFHEpke)
target_link_libraries(naive_rag OPENFHEbinfhe)

set(CMAKE_PREFIX_PATH "/usr/local/lib/OpenFHE")
find_package("OpenFHE")