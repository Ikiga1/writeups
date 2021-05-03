Mooosl
------------------------
I've spent most of the Defcon Quals 2021 reversing and pwning this challenge, so I really wanted to share our exploit :) 
We've written this together with peter, giosh, marcof, andreafioraldi and pox.

The challenge was running on Ubuntu 21.04 and it had all the protections you could imagine. 
The library was not the usual libc, but the new and hardened musl. We had to understand the logic of musl's allocator to be able to perform this attack!
You can find the challenge here: https://archive.ooo

I hope I'll be able to write a full writeup in the next days... For the moment, you can find a commented exploit in `exploit.py`

I've also written this shared library that you could `LD_PRELOAD` to hook all the `CALLOC` and `FREE` and print the addresses. I'm including this tool, as it has helped us a lot in understanding the allocation logic. Check out `libdebug.c` and `libdebug.so`. You can compile it with `musl-gcc -shared -fPIC libdebug.c -o libdebug.so`.

The flag was:  
`OOO{Hello! Mr. Feng Shui}`