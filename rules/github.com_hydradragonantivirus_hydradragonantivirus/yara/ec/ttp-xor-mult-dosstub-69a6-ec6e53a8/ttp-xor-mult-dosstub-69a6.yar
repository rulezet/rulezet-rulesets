rule TTP_XOR_MULT_DOSStub_69a6 {
  strings:
    $key_69a6 = { 3d ce [2] 49 d6 [2] 0e d4 [2] 49 c5 [2] 07 c9 [2] 0b c3 [2] 1c c8 [2] 07 86 [2] 3a }

  condition:
    any of them
}