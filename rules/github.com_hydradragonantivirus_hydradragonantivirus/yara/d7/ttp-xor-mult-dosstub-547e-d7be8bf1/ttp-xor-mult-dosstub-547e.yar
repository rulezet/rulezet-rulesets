rule TTP_XOR_MULT_DOSStub_547e {
  strings:
    $key_547e = { 00 16 [2] 74 0e [2] 33 0c [2] 74 1d [2] 3a 11 [2] 36 1b [2] 21 10 [2] 3a 5e [2] 07 }

  condition:
    any of them
}