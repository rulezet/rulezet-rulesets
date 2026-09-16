rule TTP_XOR_MULT_DOSStub_b4d6 {
  strings:
    $key_b4d6 = { e0 be [2] 94 a6 [2] d3 a4 [2] 94 b5 [2] da b9 [2] d6 b3 [2] c1 b8 [2] da f6 [2] e7 }

  condition:
    any of them
}