rule TTP_XOR_MULT_DOSStub_3a7e {
  strings:
    $key_3a7e = { 6e 16 [2] 1a 0e [2] 5d 0c [2] 1a 1d [2] 54 11 [2] 58 1b [2] 4f 10 [2] 54 5e [2] 69 }

  condition:
    any of them
}