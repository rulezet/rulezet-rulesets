rule TTP_XOR_MULT_DOSStub_a4d5 {
  strings:
    $key_a4d5 = { f0 bd [2] 84 a5 [2] c3 a7 [2] 84 b6 [2] ca ba [2] c6 b0 [2] d1 bb [2] ca f5 [2] f7 }

  condition:
    any of them
}