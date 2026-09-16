rule TTP_XOR_MULT_DOSStub_80c7 {
  strings:
    $key_80c7 = { d4 af [2] a0 b7 [2] e7 b5 [2] a0 a4 [2] ee a8 [2] e2 a2 [2] f5 a9 [2] ee e7 [2] d3 }

  condition:
    any of them
}