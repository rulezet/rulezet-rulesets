rule TTP_XOR_MULT_DOSStub_8085 {
  strings:
    $key_8085 = { d4 ed [2] a0 f5 [2] e7 f7 [2] a0 e6 [2] ee ea [2] e2 e0 [2] f5 eb [2] ee a5 [2] d3 }

  condition:
    any of them
}