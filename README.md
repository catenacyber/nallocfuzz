# nallocfuzz
Fuzzing engine with allocation failures

# Compile

```
clang -fPIE -c nallocfuzz.c -o nallocfuzz.o
ar -x /usr/local/lib/clang/*/lib/linux/libclang_rt.fuzzer_no_main-$ARCHITECTURE.a
ar rcs nallocfuzz.a nallocfuzz.o fuzzer_no_main.o
```
