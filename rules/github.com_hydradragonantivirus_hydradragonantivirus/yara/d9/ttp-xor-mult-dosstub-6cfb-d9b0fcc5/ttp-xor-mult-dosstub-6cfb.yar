rule TTP_XOR_MULT_DOSStub_6cfb {
  strings:
    $key_6cfb = { 38 93 [2] 4c 8b [2] 0b 89 [2] 4c 98 [2] 02 94 [2] 0e 9e [2] 19 95 [2] 02 db [2] 3f }

  condition:
    any of them
}