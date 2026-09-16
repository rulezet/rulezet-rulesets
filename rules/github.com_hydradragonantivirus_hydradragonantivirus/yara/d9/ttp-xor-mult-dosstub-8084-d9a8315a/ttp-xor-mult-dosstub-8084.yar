rule TTP_XOR_MULT_DOSStub_8084 {
  strings:
    $key_8084 = { d4 ec [2] a0 f4 [2] e7 f6 [2] a0 e7 [2] ee eb [2] e2 e1 [2] f5 ea [2] ee a4 [2] d3 }

  condition:
    any of them
}