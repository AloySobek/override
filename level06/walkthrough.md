## 1 - Intro

THe program asks for two inputs: `login` and `serial`
And then uses simple hash algorithm to create some sort of the hash from `login`
to check it against user provided serial

The login length must be greater than 5 and contain ASCII

## 2 - The Hack

Using [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
to de-compile the program and after some cleanup we can see the algo

```c
      hash = ((int)input[3] ^ 0x1337U) + 0x5eeded;
      for (int i = 0; i < strlen(input); i = i + 1) {
        if (input[i] < ' ') {
          return 1;
        }
        hash = hash + ((int)input[i] ^ hash) % 0x539;
      }
      if (serial == hash) {
        return 0; // Success!
      }
```

So we can simply emulate this algo with Python to generate the serial for our login

```python
s = "bnesoi"

serial = int(ord(s[3]) ^ 0x1337) + 0x5eeded

for c in s:
    serial = serial + (ord(c) ^ serial) % 0x539

print(serial)
```

The serial for login `bnesoi` is: 6232829

```sh
level06@OverRide:~$ ./level06
***********************************
*               level06           *
***********************************
-> Enter Login: bnesoi
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 6232829
Authenticated!
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp8yKj9KrWD8
```