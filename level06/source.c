int auth(char *input, unsigned int serial)
{
  unsigned int hash;

  input[strcspn(input,"\n")] = '\0';
  int len = strnlen(input,0x20);
  if ((int)len < 6) {
    return 1;
  }
  else {
    if (ptrace(0, 1, 0, 0) == -1) {
      puts("\x1b[32m.---------------------------.");
      puts("\x1b[31m| !! TAMPERING DETECTED !!  |");
      puts("\x1b[32m\'---------------------------\'");
      return 1;
    }
    else {
      hash = ((int)input[3] ^ 0x1337U) + 0x5eeded;
      for (int i = 0; i < (int)len; i = i + 1) {
        if (input[i] < ' ') {
          return 1;
        }
        hash = hash + ((int)input[i] ^ hash) % 0x539;
      }
      if (serial == hash) {
        return 0;
      }
      else {
        return 1;
      }
    }
  }
  return 1;
}


int main(void)

{
  int serial;
  char login [32];
  puts("***********************************");
  puts("*\t\tlevel06\t\t  *");
  puts("***********************************");
  printf("-> Enter Login: ");
  fgets(login,0x20,0);
  puts("***********************************");
  puts("***** NEW ACCOUNT DETECTED ********");
  puts("***********************************");
  printf("-> Enter Serial: ");
  scanf("%d", &serial);
  if (auth(login, serial) == 0) {
    puts("Authenticated!");
    system("/bin/sh");
  }
}
