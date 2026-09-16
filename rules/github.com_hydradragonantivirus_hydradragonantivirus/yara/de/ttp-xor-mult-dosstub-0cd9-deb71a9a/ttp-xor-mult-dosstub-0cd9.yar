rule TTP_XOR_MULT_DOSStub_0cd9 {
  strings:
    $key_0cd9 = { 58 b1 [2] 2c a9 [2] 6b ab [2] 2c ba [2] 62 b6 [2] 6e bc [2] 79 b7 [2] 62 f9 [2] 5f }

  condition:
    any of them
}