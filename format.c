int integer_to_string(char *buf, int bufsize, int n) {
  char *start;
  if (n < 0) {
  if (!bufsize)
    return -1;
  *buf++ = '-';
  bufsize--;
  }
  start = buf;
  do {
    int digit;
    if (!bufsize)
      return -1;
    digit = n % 10;
    if (digit < 0)
      digit *= -1;
    *buf++ = digit + '0';
    bufsize--;
    n /= 10;
  } while (n);
  if (!bufsize)
    return -1;
  *buf = 0;
  --buf;
  while (start < buf) {
    char a = *start;
    *start = *buf;
    *buf = a;
    ++start;
    --buf;
  }
  return 0;
}