rule TTP_XOR_MULT_DOSStub_8cc4 {
  strings:
    $key_8cc4 = { d8 ac [2] ac b4 [2] eb b6 [2] ac a7 [2] e2 ab [2] ee a1 [2] f9 aa [2] e2 e4 [2] df }

  condition:
    any of them
}