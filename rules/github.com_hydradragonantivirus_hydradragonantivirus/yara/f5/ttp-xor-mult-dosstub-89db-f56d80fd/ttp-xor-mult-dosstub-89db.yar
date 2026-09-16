rule TTP_XOR_MULT_DOSStub_89db {
  strings:
    $key_89db = { dd b3 [2] a9 ab [2] ee a9 [2] a9 b8 [2] e7 b4 [2] eb be [2] fc b5 [2] e7 fb [2] da }

  condition:
    any of them
}