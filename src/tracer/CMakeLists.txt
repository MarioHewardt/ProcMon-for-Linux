add_library(tracer-static STATIC
    "${CMAKE_CURRENT_SOURCE_DIR}/mock_tracer_engine.cpp"
)

add_subdirectory(ebpf)
add_subdirectory(procmonEBPF)

add_dependencies(tracer-static procmonEBPF)
target_link_libraries(tracer-static procmonEBPF)