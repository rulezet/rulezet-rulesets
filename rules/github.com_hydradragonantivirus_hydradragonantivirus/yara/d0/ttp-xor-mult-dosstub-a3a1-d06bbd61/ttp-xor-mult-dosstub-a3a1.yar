rule TTP_XOR_MULT_DOSStub_a3a1 {
  strings:
    $key_a3a1 = { f7 c9 [2] 83 d1 [2] c4 d3 [2] 83 c2 [2] cd ce [2] c1 c4 [2] d6 cf [2] cd 81 [2] f0 }

  condition:
    any of them
}