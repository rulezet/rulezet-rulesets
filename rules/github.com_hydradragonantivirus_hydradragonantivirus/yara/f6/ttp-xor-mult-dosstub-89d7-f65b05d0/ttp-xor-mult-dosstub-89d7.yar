rule TTP_XOR_MULT_DOSStub_89d7 {
  strings:
    $key_89d7 = { dd bf [2] a9 a7 [2] ee a5 [2] a9 b4 [2] e7 b8 [2] eb b2 [2] fc b9 [2] e7 f7 [2] da }

  condition:
    any of them
}