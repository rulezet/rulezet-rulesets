rule TTP_XOR_MULT_DOSStub_b4a7 {
  strings:
    $key_b4a7 = { e0 cf [2] 94 d7 [2] d3 d5 [2] 94 c4 [2] da c8 [2] d6 c2 [2] c1 c9 [2] da 87 [2] e7 }

  condition:
    any of them
}