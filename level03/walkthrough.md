## 1 - Intro

The program accepts password as number

then subtracts  from it 322424845 to use result as XOR to perform decipher
of the string 

```
Q}|u`sfg~sf{}|a3`  
```

and compares it to the 

```
Congratulations!
```

string

The algorithm is pretty simple:

Take every char of first string and perform XOR operation on it with
the number 322424845 - input

Using [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
to de-compile the program and after some cleanup we can see the algo


```c
int decrypt(int xor)
{
  char result[] = "Q}|u`sfg~sf{}|a3";
  int i = strlen(result);
  while (i--) {
    result[i] = result[i] ^ xor;
  }  

  if (!strcmp(result, "Congratulations!")) {
    system("/bin/sh");
  }
  else {
    puts("\nInvalid Password");
  }
}
```

## 2 - Hack

So we will brute force it!

But before we begin there is one note

There is the test where if the number input - 322424845 in ranges (0-10) and (16-22) algo uses this number
else
user random number

So our task is to brut force only this ranges with python


```python
for i in list(range(1, 10)) + list(range(16, 22)):
    print("^", i)
    result = ''
    for c in "Q}|u`sfg~sf{}|a3":
        result += chr(ord(c) ^ i)
    if result == "Congratulations!":
        print("XOR: ", i, "WORKS!")


^ 1
^ 2
^ 3
^ 4
^ 5
^ 6
^ 7
^ 8
^ 9
^ 16
^ 17
^ 18
XOR:  18 WORKS!
^ 19
^ 20
^ 21
```

So we found only valid for XOR value for given ranged

use

322424845 - 18 = 322424827

to crack the program

```sh
level03@OverRide:~$ ./level03 
***********************************
*               level03         **
***********************************
Password:322424827
$ whoami
level04
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```