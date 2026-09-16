rule TTP_XOR_MULT_DOSStub_b3a7 {
  strings:
    $key_b3a7 = { e7 cf [2] 93 d7 [2] d4 d5 [2] 93 c4 [2] dd c8 [2] d1 c2 [2] c6 c9 [2] dd 87 [2] e0 }

  condition:
    any of them
}