# bf_jit
Brainfuck JIT compiler inspired by https://github.com/tsoding/bfjit

The goal is to not hardcode the machine code gadgets, but use the C compiler/assembler to generate them during normal compilation.

At first I hoped I could define the "gadgets" using C code instead and copy the generated machine code, but I couldn't get that to work,
so I used inline assembly instead.
