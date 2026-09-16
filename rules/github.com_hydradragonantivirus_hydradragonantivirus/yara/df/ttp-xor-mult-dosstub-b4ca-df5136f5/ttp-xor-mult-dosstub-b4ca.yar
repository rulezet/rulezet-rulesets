rule TTP_XOR_MULT_DOSStub_b4ca {
  strings:
    $key_b4ca = { e0 a2 [2] 94 ba [2] d3 b8 [2] 94 a9 [2] da a5 [2] d6 af [2] c1 a4 [2] da ea [2] e7 }

  condition:
    any of them
}