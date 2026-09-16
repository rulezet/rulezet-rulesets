rule TTP_XOR_MULT_DOSStub_5442 {
  strings:
    $key_5442 = { 00 2a [2] 74 32 [2] 33 30 [2] 74 21 [2] 3a 2d [2] 36 27 [2] 21 2c [2] 3a 62 [2] 07 }

  condition:
    any of them
}