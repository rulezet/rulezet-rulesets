rule TTP_XOR_MULT_DOSStub_755e {
  strings:
    $key_755e = { 21 36 [2] 55 2e [2] 12 2c [2] 55 3d [2] 1b 31 [2] 17 3b [2] 00 30 [2] 1b 7e [2] 26 }

  condition:
    any of them
}