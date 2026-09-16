rule TTP_XOR_MULT_DOSStub_b485 {
  strings:
    $key_b485 = { e0 ed [2] 94 f5 [2] d3 f7 [2] 94 e6 [2] da ea [2] d6 e0 [2] c1 eb [2] da a5 [2] e7 }

  condition:
    any of them
}