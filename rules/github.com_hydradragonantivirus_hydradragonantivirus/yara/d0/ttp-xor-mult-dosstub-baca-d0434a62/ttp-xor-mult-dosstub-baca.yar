rule TTP_XOR_MULT_DOSStub_baca {
  strings:
    $key_baca = { ee a2 [2] 9a ba [2] dd b8 [2] 9a a9 [2] d4 a5 [2] d8 af [2] cf a4 [2] d4 ea [2] e9 }

  condition:
    any of them
}