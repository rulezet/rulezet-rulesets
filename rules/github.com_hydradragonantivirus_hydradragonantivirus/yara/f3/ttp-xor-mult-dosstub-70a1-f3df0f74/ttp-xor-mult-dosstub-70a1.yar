rule TTP_XOR_MULT_DOSStub_70a1 {
  strings:
    $key_70a1 = { 24 c9 [2] 50 d1 [2] 17 d3 [2] 50 c2 [2] 1e ce [2] 12 c4 [2] 05 cf [2] 1e 81 [2] 23 }

  condition:
    any of them
}