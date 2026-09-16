rule TTP_XOR_MULT_DOSStub_86d3 {
  strings:
    $key_86d3 = { d2 bb [2] a6 a3 [2] e1 a1 [2] a6 b0 [2] e8 bc [2] e4 b6 [2] f3 bd [2] e8 f3 [2] d5 }

  condition:
    any of them
}