rule TTP_XOR_MULT_DOSStub_b4b9 {
  strings:
    $key_b4b9 = { e0 d1 [2] 94 c9 [2] d3 cb [2] 94 da [2] da d6 [2] d6 dc [2] c1 d7 [2] da 99 [2] e7 }

  condition:
    any of them
}