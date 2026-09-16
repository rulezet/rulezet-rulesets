rule TTP_XOR_MULT_DOSStub_b4c6 {
  strings:
    $key_b4c6 = { e0 ae [2] 94 b6 [2] d3 b4 [2] 94 a5 [2] da a9 [2] d6 a3 [2] c1 a8 [2] da e6 [2] e7 }

  condition:
    any of them
}