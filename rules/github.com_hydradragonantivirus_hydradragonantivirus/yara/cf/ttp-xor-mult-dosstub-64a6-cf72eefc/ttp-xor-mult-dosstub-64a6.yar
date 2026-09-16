rule TTP_XOR_MULT_DOSStub_64a6 {
  strings:
    $key_64a6 = { 30 ce [2] 44 d6 [2] 03 d4 [2] 44 c5 [2] 0a c9 [2] 06 c3 [2] 11 c8 [2] 0a 86 [2] 37 }

  condition:
    any of them
}