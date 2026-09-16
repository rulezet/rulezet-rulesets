rule TTP_XOR_MULT_DOSStub_775e {
  strings:
    $key_775e = { 23 36 [2] 57 2e [2] 10 2c [2] 57 3d [2] 19 31 [2] 15 3b [2] 02 30 [2] 19 7e [2] 24 }

  condition:
    any of them
}