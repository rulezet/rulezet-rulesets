rule TTP_XOR_MULT_DOSStub_426d {
  strings:
    $key_426d = { 16 05 [2] 62 1d [2] 25 1f [2] 62 0e [2] 2c 02 [2] 20 08 [2] 37 03 [2] 2c 4d [2] 11 }

  condition:
    any of them
}