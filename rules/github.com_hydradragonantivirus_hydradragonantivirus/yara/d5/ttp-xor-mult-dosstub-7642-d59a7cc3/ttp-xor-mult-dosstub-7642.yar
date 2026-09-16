rule TTP_XOR_MULT_DOSStub_7642 {
  strings:
    $key_7642 = { 22 2a [2] 56 32 [2] 11 30 [2] 56 21 [2] 18 2d [2] 14 27 [2] 03 2c [2] 18 62 [2] 25 }

  condition:
    any of them
}