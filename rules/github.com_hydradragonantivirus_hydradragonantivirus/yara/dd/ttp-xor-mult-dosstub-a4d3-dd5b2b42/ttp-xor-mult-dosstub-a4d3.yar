rule TTP_XOR_MULT_DOSStub_a4d3 {
  strings:
    $key_a4d3 = { f0 bb [2] 84 a3 [2] c3 a1 [2] 84 b0 [2] ca bc [2] c6 b6 [2] d1 bd [2] ca f3 [2] f7 }

  condition:
    any of them
}