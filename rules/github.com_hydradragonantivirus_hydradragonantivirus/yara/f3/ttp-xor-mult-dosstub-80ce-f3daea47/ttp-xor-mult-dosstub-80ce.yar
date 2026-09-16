rule TTP_XOR_MULT_DOSStub_80ce {
  strings:
    $key_80ce = { d4 a6 [2] a0 be [2] e7 bc [2] a0 ad [2] ee a1 [2] e2 ab [2] f5 a0 [2] ee ee [2] d3 }

  condition:
    any of them
}