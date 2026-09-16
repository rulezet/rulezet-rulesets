rule TTP_XOR_MULT_DOSStub_b3d3 {
  strings:
    $key_b3d3 = { e7 bb [2] 93 a3 [2] d4 a1 [2] 93 b0 [2] dd bc [2] d1 b6 [2] c6 bd [2] dd f3 [2] e0 }

  condition:
    any of them
}