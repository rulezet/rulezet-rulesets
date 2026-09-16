rule TTP_XOR_MULT_DOSStub_39a6 {
  strings:
    $key_39a6 = { 6d ce [2] 19 d6 [2] 5e d4 [2] 19 c5 [2] 57 c9 [2] 5b c3 [2] 4c c8 [2] 57 86 [2] 6a }

  condition:
    any of them
}