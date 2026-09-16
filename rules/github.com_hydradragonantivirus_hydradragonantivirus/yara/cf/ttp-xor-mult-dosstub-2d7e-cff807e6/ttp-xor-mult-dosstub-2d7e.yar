rule TTP_XOR_MULT_DOSStub_2d7e {
  strings:
    $key_2d7e = { 79 16 [2] 0d 0e [2] 4a 0c [2] 0d 1d [2] 43 11 [2] 4f 1b [2] 58 10 [2] 43 5e [2] 7e }

  condition:
    any of them
}