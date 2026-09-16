rule TTP_XOR_MULT_DOSStub_7ffb {
  strings:
    $key_7ffb = { 2b 93 [2] 5f 8b [2] 18 89 [2] 5f 98 [2] 11 94 [2] 1d 9e [2] 0a 95 [2] 11 db [2] 2c }

  condition:
    any of them
}