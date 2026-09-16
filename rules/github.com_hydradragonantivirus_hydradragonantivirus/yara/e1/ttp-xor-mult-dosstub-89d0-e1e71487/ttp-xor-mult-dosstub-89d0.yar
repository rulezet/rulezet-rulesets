rule TTP_XOR_MULT_DOSStub_89d0 {
  strings:
    $key_89d0 = { dd b8 [2] a9 a0 [2] ee a2 [2] a9 b3 [2] e7 bf [2] eb b5 [2] fc be [2] e7 f0 [2] da }

  condition:
    any of them
}