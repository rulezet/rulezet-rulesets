rule TTP_XOR_MULT_DOSStub_2d4e {
  strings:
    $key_2d4e = { 79 26 [2] 0d 3e [2] 4a 3c [2] 0d 2d [2] 43 21 [2] 4f 2b [2] 58 20 [2] 43 6e [2] 7e }

  condition:
    any of them
}