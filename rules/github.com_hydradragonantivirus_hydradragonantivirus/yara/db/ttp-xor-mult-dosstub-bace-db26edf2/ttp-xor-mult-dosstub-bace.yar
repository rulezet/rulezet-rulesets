rule TTP_XOR_MULT_DOSStub_bace {
  strings:
    $key_bace = { ee a6 [2] 9a be [2] dd bc [2] 9a ad [2] d4 a1 [2] d8 ab [2] cf a0 [2] d4 ee [2] e9 }

  condition:
    any of them
}