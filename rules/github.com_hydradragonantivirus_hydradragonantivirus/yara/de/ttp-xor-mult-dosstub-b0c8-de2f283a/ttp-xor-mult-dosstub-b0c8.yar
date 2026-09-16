rule TTP_XOR_MULT_DOSStub_b0c8 {
  strings:
    $key_b0c8 = { e4 a0 [2] 90 b8 [2] d7 ba [2] 90 ab [2] de a7 [2] d2 ad [2] c5 a6 [2] de e8 [2] e3 }

  condition:
    any of them
}