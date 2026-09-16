rule TTP_XOR_MULT_DOSStub_97a1 {
  strings:
    $key_97a1 = { c3 c9 [2] b7 d1 [2] f0 d3 [2] b7 c2 [2] f9 ce [2] f5 c4 [2] e2 cf [2] f9 81 [2] c4 }

  condition:
    any of them
}