rule TTP_XOR_MULT_DOSStub_6cb4 {
  strings:
    $key_6cb4 = { 38 dc [2] 4c c4 [2] 0b c6 [2] 4c d7 [2] 02 db [2] 0e d1 [2] 19 da [2] 02 94 [2] 3f }

  condition:
    any of them
}