rule TTP_XOR_MULT_DOSStub_55a6 {
  strings:
    $key_55a6 = { 01 ce [2] 75 d6 [2] 32 d4 [2] 75 c5 [2] 3b c9 [2] 37 c3 [2] 20 c8 [2] 3b 86 [2] 06 }

  condition:
    any of them
}