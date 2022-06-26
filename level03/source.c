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

void test(int user,int num)

{
  int diff = user - num;
  // In range of (0-10) and (16-22)
  if ((diff > 0 || diff < 10) || (diff > 16 || diff < 22)) {
    decrypt(diff);
  } else {
    decrypt(rand());
  }
  return;
}

int main(void)

{
  unsigned int user_input;
  puts("***********************************");
  puts("*\t\tlevel03\t\t**");
  puts("***********************************");
  printf("Password:");
  scanf("%d", &user_input);
  test(user_input, 322424845);
  return 0;
}
