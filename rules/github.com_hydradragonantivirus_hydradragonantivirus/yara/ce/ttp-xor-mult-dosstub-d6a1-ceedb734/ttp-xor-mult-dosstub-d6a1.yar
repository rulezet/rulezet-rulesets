rule TTP_XOR_MULT_DOSStub_d6a1 {
  strings:
    $key_d6a1 = { 82 c9 [2] f6 d1 [2] b1 d3 [2] f6 c2 [2] b8 ce [2] b4 c4 [2] a3 cf [2] b8 81 [2] 85 }

  condition:
    any of them
}