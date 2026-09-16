rule TTP_XOR_MULT_DOSStub_b1a1 {
  strings:
    $key_b1a1 = { e5 c9 [2] 91 d1 [2] d6 d3 [2] 91 c2 [2] df ce [2] d3 c4 [2] c4 cf [2] df 81 [2] e2 }

  condition:
    any of them
}