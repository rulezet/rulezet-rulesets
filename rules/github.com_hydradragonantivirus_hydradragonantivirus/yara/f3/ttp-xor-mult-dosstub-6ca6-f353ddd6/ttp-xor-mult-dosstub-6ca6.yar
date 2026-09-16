rule TTP_XOR_MULT_DOSStub_6ca6 {
  strings:
    $key_6ca6 = { 38 ce [2] 4c d6 [2] 0b d4 [2] 4c c5 [2] 02 c9 [2] 0e c3 [2] 19 c8 [2] 02 86 [2] 3f }

  condition:
    any of them
}