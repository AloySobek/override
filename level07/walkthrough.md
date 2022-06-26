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