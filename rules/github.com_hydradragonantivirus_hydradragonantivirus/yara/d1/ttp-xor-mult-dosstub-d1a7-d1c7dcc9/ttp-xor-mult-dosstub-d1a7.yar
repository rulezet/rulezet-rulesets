rule TTP_XOR_MULT_DOSStub_d1a7 {
  strings:
    $key_d1a7 = { 85 cf [2] f1 d7 [2] b6 d5 [2] f1 c4 [2] bf c8 [2] b3 c2 [2] a4 c9 [2] bf 87 [2] 82 }

  condition:
    any of them
}