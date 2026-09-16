rule TTP_XOR_MULT_DOSStub_b0d5 {
  strings:
    $key_b0d5 = { e4 bd [2] 90 a5 [2] d7 a7 [2] 90 b6 [2] de ba [2] d2 b0 [2] c5 bb [2] de f5 [2] e3 }

  condition:
    any of them
}