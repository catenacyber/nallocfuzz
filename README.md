# nallocfuzz
Fuzzing engine with allocation failures

# Compile

```
clang -fPIE -c nallocfuzz.c -o nallocfuzz.o
ar -x /usr/local/lib/clang/*/lib/linux/libclang_rt.fuzzer_no_main-$ARCHITECTURE.a
ar rcs nallocfuzz.a nallocfuzz.o fuzzer_no_main.o
```

# Reproduce outside of fuzzer

```
clang -fPIC -I. -c nallocrun.c -o nallocrun.o
clang -fPIC -shared -o nallocrun.so nallocrun.o libbacktrace/.libs/*.o
export NALLOC_RUN_SIZE=123
export NALLOC_RUN_OPERATION=realloc
export NALLOC_RUN_CALLER=caller
LD_PRELOAD=/path/to/nallocrun.so /path/to/prog args
```

This does not work with ASAN which takes precedence over `LD_PRELOAD`
Other solution is to get nallocrun statically compiled into your binary...
