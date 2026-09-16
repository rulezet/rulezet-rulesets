rule TTP_XOR_MULT_DOSStub_b4b4 {
  strings:
    $key_b4b4 = { e0 dc [2] 94 c4 [2] d3 c6 [2] 94 d7 [2] da db [2] d6 d1 [2] c1 da [2] da 94 [2] e7 }

  condition:
    any of them
}