add_executable( chacha20_poly1305_bench bench.cxx )

target_link_libraries( chacha20_poly1305_bench PRIVATE chacha20_poly1305 )
target_compile_features( chacha20_poly1305_bench PRIVATE cxx_std_23 )
