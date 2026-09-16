rule TTP_XOR_MULT_DOSStub_8088 {
  strings:
    $key_8088 = { d4 e0 [2] a0 f8 [2] e7 fa [2] a0 eb [2] ee e7 [2] e2 ed [2] f5 e6 [2] ee a8 [2] d3 }

  condition:
    any of them
}