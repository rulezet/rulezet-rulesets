rule TTP_XOR_MULT_DOSStub_315e {
  strings:
    $key_315e = { 65 36 [2] 11 2e [2] 56 2c [2] 11 3d [2] 5f 31 [2] 53 3b [2] 44 30 [2] 5f 7e [2] 62 }

  condition:
    any of them
}