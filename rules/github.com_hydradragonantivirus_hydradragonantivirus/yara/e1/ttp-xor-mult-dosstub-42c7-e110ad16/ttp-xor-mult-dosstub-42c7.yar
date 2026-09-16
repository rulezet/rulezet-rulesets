rule TTP_XOR_MULT_DOSStub_42c7 {
  strings:
    $key_42c7 = { 16 af [2] 62 b7 [2] 25 b5 [2] 62 a4 [2] 2c a8 [2] 20 a2 [2] 37 a9 [2] 2c e7 [2] 11 }

  condition:
    any of them
}