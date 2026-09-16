rule TTP_XOR_MULT_DOSStub_52a6 {
  strings:
    $key_52a6 = { 06 ce [2] 72 d6 [2] 35 d4 [2] 72 c5 [2] 3c c9 [2] 30 c3 [2] 27 c8 [2] 3c 86 [2] 01 }

  condition:
    any of them
}