rule TTP_XOR_MULT_DOSStub_89d2 {
  strings:
    $key_89d2 = { dd ba [2] a9 a2 [2] ee a0 [2] a9 b1 [2] e7 bd [2] eb b7 [2] fc bc [2] e7 f2 [2] da }

  condition:
    any of them
}