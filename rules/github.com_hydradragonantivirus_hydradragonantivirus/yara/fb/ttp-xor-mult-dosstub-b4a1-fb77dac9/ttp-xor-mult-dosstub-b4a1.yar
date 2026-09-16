rule TTP_XOR_MULT_DOSStub_b4a1 {
  strings:
    $key_b4a1 = { e0 c9 [2] 94 d1 [2] d3 d3 [2] 94 c2 [2] da ce [2] d6 c4 [2] c1 cf [2] da 81 [2] e7 }

  condition:
    any of them
}