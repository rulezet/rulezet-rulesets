rule TTP_XOR_MULT_DOSStub_cec0 {
  strings:
    $key_cec0 = { 9a a8 [2] ee b0 [2] a9 b2 [2] ee a3 [2] a0 af [2] ac a5 [2] bb ae [2] a0 e0 [2] 9d }

  condition:
    any of them
}