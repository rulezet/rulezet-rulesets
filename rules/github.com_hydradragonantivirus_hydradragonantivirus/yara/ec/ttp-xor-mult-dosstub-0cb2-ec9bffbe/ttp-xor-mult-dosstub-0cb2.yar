rule TTP_XOR_MULT_DOSStub_0cb2 {
  strings:
    $key_0cb2 = { 58 da [2] 2c c2 [2] 6b c0 [2] 2c d1 [2] 62 dd [2] 6e d7 [2] 79 dc [2] 62 92 [2] 5f }

  condition:
    any of them
}