rule TTP_XOR_MULT_DOSStub_40a6 {
  strings:
    $key_40a6 = { 14 ce [2] 60 d6 [2] 27 d4 [2] 60 c5 [2] 2e c9 [2] 22 c3 [2] 35 c8 [2] 2e 86 [2] 13 }

  condition:
    any of them
}