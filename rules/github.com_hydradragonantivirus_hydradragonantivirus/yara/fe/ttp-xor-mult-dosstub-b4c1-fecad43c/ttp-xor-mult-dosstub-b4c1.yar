rule TTP_XOR_MULT_DOSStub_b4c1 {
  strings:
    $key_b4c1 = { e0 a9 [2] 94 b1 [2] d3 b3 [2] 94 a2 [2] da ae [2] d6 a4 [2] c1 af [2] da e1 [2] e7 }

  condition:
    any of them
}