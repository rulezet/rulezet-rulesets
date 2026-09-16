rule TTP_XOR_MULT_DOSStub_175e {
  strings:
    $key_175e = { 43 36 [2] 37 2e [2] 70 2c [2] 37 3d [2] 79 31 [2] 75 3b [2] 62 30 [2] 79 7e [2] 44 }

  condition:
    any of them
}