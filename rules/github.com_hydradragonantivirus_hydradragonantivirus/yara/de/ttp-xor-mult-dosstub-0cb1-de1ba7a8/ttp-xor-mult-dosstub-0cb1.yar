rule TTP_XOR_MULT_DOSStub_0cb1 {
  strings:
    $key_0cb1 = { 58 d9 [2] 2c c1 [2] 6b c3 [2] 2c d2 [2] 62 de [2] 6e d4 [2] 79 df [2] 62 91 [2] 5f }

  condition:
    any of them
}