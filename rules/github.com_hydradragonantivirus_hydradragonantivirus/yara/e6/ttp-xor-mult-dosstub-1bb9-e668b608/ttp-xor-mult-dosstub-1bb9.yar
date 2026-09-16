rule TTP_XOR_MULT_DOSStub_1bb9 {
  strings:
    $key_1bb9 = { 4f d1 [2] 3b c9 [2] 7c cb [2] 3b da [2] 75 d6 [2] 79 dc [2] 6e d7 [2] 75 99 [2] 48 }

  condition:
    any of them
}