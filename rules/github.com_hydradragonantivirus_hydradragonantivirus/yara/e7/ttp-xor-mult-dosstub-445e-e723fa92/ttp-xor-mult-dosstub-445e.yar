rule TTP_XOR_MULT_DOSStub_445e {
  strings:
    $key_445e = { 10 36 [2] 64 2e [2] 23 2c [2] 64 3d [2] 2a 31 [2] 26 3b [2] 31 30 [2] 2a 7e [2] 17 }

  condition:
    any of them
}