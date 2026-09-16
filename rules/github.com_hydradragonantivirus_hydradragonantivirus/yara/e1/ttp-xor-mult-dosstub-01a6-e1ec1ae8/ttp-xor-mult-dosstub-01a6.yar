rule TTP_XOR_MULT_DOSStub_01a6 {
  strings:
    $key_01a6 = { 55 ce [2] 21 d6 [2] 66 d4 [2] 21 c5 [2] 6f c9 [2] 63 c3 [2] 74 c8 [2] 6f 86 [2] 52 }

  condition:
    any of them
}