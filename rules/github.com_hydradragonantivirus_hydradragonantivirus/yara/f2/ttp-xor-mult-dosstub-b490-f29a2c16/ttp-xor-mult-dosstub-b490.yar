rule TTP_XOR_MULT_DOSStub_b490 {
  strings:
    $key_b490 = { e0 f8 [2] 94 e0 [2] d3 e2 [2] 94 f3 [2] da ff [2] d6 f5 [2] c1 fe [2] da b0 [2] e7 }

  condition:
    any of them
}