rule TTP_XOR_MULT_DOSStub_78b9 {
  strings:
    $key_78b9 = { 2c d1 [2] 58 c9 [2] 1f cb [2] 58 da [2] 16 d6 [2] 1a dc [2] 0d d7 [2] 16 99 [2] 2b }

  condition:
    any of them
}