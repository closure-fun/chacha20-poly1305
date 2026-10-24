add_executable( chacha20_poly1305_tests tests.cxx )

target_link_libraries( chacha20_poly1305_tests PRIVATE chacha20_poly1305 )
target_compile_features( chacha20_poly1305_tests PRIVATE cxx_std_23 )

add_test( NAME chacha20_poly1305_tests COMMAND $<TARGET_FILE:chacha20_poly1305_tests> )
