char a_user_name[256];

int verify_user_name(void)
{
  return strncmp(a_user_name, "dat_wil", 7);
}

int verify_user_pass(char *pass)
{
  return strncmp(pass, "admin", 5);
}

int main(void)
{
  int uVar1;
  int iVar2;
  int *puVar3;
  int password_buffer [16];
  int pass_verify_result;
  
  memset(password_buffer, 0, sizeof(password_buffer));

  puts("********* ADMIN LOGIN PROMPT *********");
  printf("Enter Username: ");

  fgets(a_user_name, 256, 0);
  if (verify_user_name() == 0) {
    puts("Enter Password: ");

    // Unsafe fgets here!
    // Reading 100 into buffer of 16 length!
    fgets((char *)password_buffer,100,0);
    pass_verify_result = verify_user_pass(password_buffer);
    if ((pass_verify_result == 0) || (pass_verify_result != 0)) {
      puts("nope, incorrect password...\n");
      return 1;
    }
    else {
      return 0;
    }
  }
  else {
    puts("nope, incorrect username...\n");
    return 1;
  }
}
