
set(libbpf_SOURCE_DIR ${CMAKE_BINARY_DIR}/src/tracer/procmonEBPF/libbpf/src/libbpf)

target_include_directories(tracer-static PUBLIC
                           "${libbpf_SOURCE_DIR}/src"
                           "${libbpf_SOURCE_DIR}/include"
                           "${libbpf_SOURCE_DIR}/include/asm"
                           "${libbpf_SOURCE_DIR}/include/linux"
                           "${libbpf_SOURCE_DIR}/include/tools"
                           "${libbpf_SOURCE_DIR}/include/uapi"
                           "${libbpf_SOURCE_DIR}/include/uapi/linux"
                           "/usr/include"
                           )

target_sources(tracer-static PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/ebpf_tracer_engine.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/raw_ebpf_event.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/syscall_schema.cpp"
)



