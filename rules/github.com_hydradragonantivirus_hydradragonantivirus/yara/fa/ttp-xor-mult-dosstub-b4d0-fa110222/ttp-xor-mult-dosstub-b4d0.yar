rule TTP_XOR_MULT_DOSStub_b4d0 {
  strings:
    $key_b4d0 = { e0 b8 [2] 94 a0 [2] d3 a2 [2] 94 b3 [2] da bf [2] d6 b5 [2] c1 be [2] da f0 [2] e7 }

  condition:
    any of them
}