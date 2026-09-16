rule TTP_XOR_MULT_DOSStub_80cc {
  strings:
    $key_80cc = { d4 a4 [2] a0 bc [2] e7 be [2] a0 af [2] ee a3 [2] e2 a9 [2] f5 a2 [2] ee ec [2] d3 }

  condition:
    any of them
}