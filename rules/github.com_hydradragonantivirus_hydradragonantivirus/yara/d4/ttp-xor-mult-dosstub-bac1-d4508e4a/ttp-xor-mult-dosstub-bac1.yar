rule TTP_XOR_MULT_DOSStub_bac1 {
  strings:
    $key_bac1 = { ee a9 [2] 9a b1 [2] dd b3 [2] 9a a2 [2] d4 ae [2] d8 a4 [2] cf af [2] d4 e1 [2] e9 }

  condition:
    any of them
}