rule TTP_XOR_MULT_DOSStub_f1d3 {
  strings:
    $key_f1d3 = { a5 bb [2] d1 a3 [2] 96 a1 [2] d1 b0 [2] 9f bc [2] 93 b6 [2] 84 bd [2] 9f f3 [2] a2 }

  condition:
    any of them
}