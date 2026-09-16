rule TTP_XOR_MULT_DOSStub_a6d3 {
  strings:
    $key_a6d3 = { f2 bb [2] 86 a3 [2] c1 a1 [2] 86 b0 [2] c8 bc [2] c4 b6 [2] d3 bd [2] c8 f3 [2] f5 }

  condition:
    any of them
}