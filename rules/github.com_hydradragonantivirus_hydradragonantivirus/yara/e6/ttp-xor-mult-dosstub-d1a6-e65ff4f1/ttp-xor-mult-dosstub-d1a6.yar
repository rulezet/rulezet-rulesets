rule TTP_XOR_MULT_DOSStub_d1a6 {
  strings:
    $key_d1a6 = { 85 ce [2] f1 d6 [2] b6 d4 [2] f1 c5 [2] bf c9 [2] b3 c3 [2] a4 c8 [2] bf 86 [2] 82 }

  condition:
    any of them
}