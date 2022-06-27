void main(void)
{
  char user_input[100];
  unsigned int count;
  unsigned int len;

  fgets(user_input,100,0);
  count = 0;
  len = strlen(user_input);

  do {
    if (user_input[count] > '@' && user_input[count] < '[') {
      user_input[count] = user_input[count] ^ 0x20;
    }
    count++;
  } while(count < len);
  printf(user_input);
  exit(0);
}
