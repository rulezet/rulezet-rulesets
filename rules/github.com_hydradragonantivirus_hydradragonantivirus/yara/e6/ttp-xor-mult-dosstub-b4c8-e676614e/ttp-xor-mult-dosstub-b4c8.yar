rule TTP_XOR_MULT_DOSStub_b4c8 {
  strings:
    $key_b4c8 = { e0 a0 [2] 94 b8 [2] d3 ba [2] 94 ab [2] da a7 [2] d6 ad [2] c1 a6 [2] da e8 [2] e7 }

  condition:
    any of them
}