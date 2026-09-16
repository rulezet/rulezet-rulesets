rule TTP_XOR_MULT_DOSStub_8cc7 {
  strings:
    $key_8cc7 = { d8 af [2] ac b7 [2] eb b5 [2] ac a4 [2] e2 a8 [2] ee a2 [2] f9 a9 [2] e2 e7 [2] df }

  condition:
    any of them
}