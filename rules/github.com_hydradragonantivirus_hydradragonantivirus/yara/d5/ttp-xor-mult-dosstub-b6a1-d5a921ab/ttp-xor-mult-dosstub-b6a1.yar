rule TTP_XOR_MULT_DOSStub_b6a1 {
  strings:
    $key_b6a1 = { e2 c9 [2] 96 d1 [2] d1 d3 [2] 96 c2 [2] d8 ce [2] d4 c4 [2] c3 cf [2] d8 81 [2] e5 }

  condition:
    any of them
}