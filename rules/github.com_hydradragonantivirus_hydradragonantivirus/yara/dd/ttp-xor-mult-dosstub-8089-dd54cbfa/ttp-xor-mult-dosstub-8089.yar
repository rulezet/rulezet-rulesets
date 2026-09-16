rule TTP_XOR_MULT_DOSStub_8089 {
  strings:
    $key_8089 = { d4 e1 [2] a0 f9 [2] e7 fb [2] a0 ea [2] ee e6 [2] e2 ec [2] f5 e7 [2] ee a9 [2] d3 }

  condition:
    any of them
}