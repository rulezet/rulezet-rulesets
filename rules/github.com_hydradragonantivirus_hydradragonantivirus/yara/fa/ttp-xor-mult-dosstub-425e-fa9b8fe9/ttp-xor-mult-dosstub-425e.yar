rule TTP_XOR_MULT_DOSStub_425e {
  strings:
    $key_425e = { 16 36 [2] 62 2e [2] 25 2c [2] 62 3d [2] 2c 31 [2] 20 3b [2] 37 30 [2] 2c 7e [2] 11 }

  condition:
    any of them
}