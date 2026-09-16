rule TTP_XOR_MULT_DOSStub_76a6 {
  strings:
    $key_76a6 = { 22 ce [2] 56 d6 [2] 11 d4 [2] 56 c5 [2] 18 c9 [2] 14 c3 [2] 03 c8 [2] 18 86 [2] 25 }

  condition:
    any of them
}