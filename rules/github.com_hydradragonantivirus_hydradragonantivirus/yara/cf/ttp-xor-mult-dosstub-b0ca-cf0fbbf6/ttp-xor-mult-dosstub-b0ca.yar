rule TTP_XOR_MULT_DOSStub_b0ca {
  strings:
    $key_b0ca = { e4 a2 [2] 90 ba [2] d7 b8 [2] 90 a9 [2] de a5 [2] d2 af [2] c5 a4 [2] de ea [2] e3 }

  condition:
    any of them
}