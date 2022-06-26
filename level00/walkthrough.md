# Walkthrough

## Context

### Binary info

```bash
level00@OverRide:~$ ls -l
total 8
-rwsr-s---+ 1 level01 users 7280 Sep 10  2016 level00
level00@OverRide:~$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:password

Invalid Password!
level00@OverRide:~$ file level00
level00: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x20352633f776024748e9f8a5ebab6686df488bcf, not stripped
```

An elf binary for intel 80386 arch with level01 privileges


### Functions

```assembly
(gdb) info functions
All defined functions:

Non-debugging symbols:
...
0x08048494  main
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

### 'main' dissambly

```assembly
(gdb) disas main
Dump of assembler code for function main:
...
   0x080484de <+74>:    call   0x80483d0 <__isoc99_scanf@plt> ; Reading password onto 0x1c(%esp)
   0x080484e3 <+79>:    mov    0x1c(%esp),%eax                ; Moving passwords onto %eax
   0x080484e7 <+83>:    cmp    $0x149c,%eax                   ; Compares hard-coded password with our password 0x149c(hex) = 5276(decimal)
   0x080484ec <+88>:    jne    0x804850d <main+121>           ; If passwords are matched allows to call 'system'
...
   0x08048501 <+109>:   call   0x80483a0 <system@plt>         ; 'system' call
...
End of assembler dump.
```

## Exploit

We've seen how binary just compares our input password with hard-coded one inside binary without hash or something. We can just use this passwords, haha.

### Getting .pass

```bash
level00@OverRide:~$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:5276

Authenticated!
$ whoami
level01
$ cat /home/users/level01/.pass
uSq2ehEGT6c9S24zbshexZQBXUGrncxn5sD5QfGL
```