rule TTP_XOR_MULT_DOSStub_8ccd {
  strings:
    $key_8ccd = { d8 a5 [2] ac bd [2] eb bf [2] ac ae [2] e2 a2 [2] ee a8 [2] f9 a3 [2] e2 ed [2] df }

  condition:
    any of them
}