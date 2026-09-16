rule TTP_XOR_MULT_DOSStub_bacb {
  strings:
    $key_bacb = { ee a3 [2] 9a bb [2] dd b9 [2] 9a a8 [2] d4 a4 [2] d8 ae [2] cf a5 [2] d4 eb [2] e9 }

  condition:
    any of them
}