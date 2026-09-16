rule TTP_XOR_MULT_DOSStub_46a6 {
  strings:
    $key_46a6 = { 12 ce [2] 66 d6 [2] 21 d4 [2] 66 c5 [2] 28 c9 [2] 24 c3 [2] 33 c8 [2] 28 86 [2] 15 }

  condition:
    any of them
}