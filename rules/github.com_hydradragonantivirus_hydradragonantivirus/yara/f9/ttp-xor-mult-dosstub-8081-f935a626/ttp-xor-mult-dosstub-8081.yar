rule TTP_XOR_MULT_DOSStub_8081 {
  strings:
    $key_8081 = { d4 e9 [2] a0 f1 [2] e7 f3 [2] a0 e2 [2] ee ee [2] e2 e4 [2] f5 ef [2] ee a1 [2] d3 }

  condition:
    any of them
}