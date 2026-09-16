rule TTP_XOR_MULT_DOSStub_b6a7 {
  strings:
    $key_b6a7 = { e2 cf [2] 96 d7 [2] d1 d5 [2] 96 c4 [2] d8 c8 [2] d4 c2 [2] c3 c9 [2] d8 87 [2] e5 }

  condition:
    any of them
}