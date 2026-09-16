rule TTP_XOR_MULT_DOSStub_b1d3 {
  strings:
    $key_b1d3 = { e5 bb [2] 91 a3 [2] d6 a1 [2] 91 b0 [2] df bc [2] d3 b6 [2] c4 bd [2] df f3 [2] e2 }

  condition:
    any of them
}