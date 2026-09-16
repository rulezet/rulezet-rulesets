rule TTP_XOR_MULT_DOSStub_b0d3 {
  strings:
    $key_b0d3 = { e4 bb [2] 90 a3 [2] d7 a1 [2] 90 b0 [2] de bc [2] d2 b6 [2] c5 bd [2] de f3 [2] e3 }

  condition:
    any of them
}