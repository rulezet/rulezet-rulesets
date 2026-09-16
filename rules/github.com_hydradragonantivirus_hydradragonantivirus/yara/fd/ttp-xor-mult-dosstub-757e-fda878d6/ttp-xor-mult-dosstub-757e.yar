rule TTP_XOR_MULT_DOSStub_757e {
  strings:
    $key_757e = { 21 16 [2] 55 0e [2] 12 0c [2] 55 1d [2] 1b 11 [2] 17 1b [2] 00 10 [2] 1b 5e [2] 26 }

  condition:
    any of them
}