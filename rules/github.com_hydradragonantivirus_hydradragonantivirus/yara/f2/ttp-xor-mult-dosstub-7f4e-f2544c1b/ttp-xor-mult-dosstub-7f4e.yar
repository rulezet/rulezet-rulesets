rule TTP_XOR_MULT_DOSStub_7f4e {
  strings:
    $key_7f4e = { 2b 26 [2] 5f 3e [2] 18 3c [2] 5f 2d [2] 11 21 [2] 1d 2b [2] 0a 20 [2] 11 6e [2] 2c }

  condition:
    any of them
}