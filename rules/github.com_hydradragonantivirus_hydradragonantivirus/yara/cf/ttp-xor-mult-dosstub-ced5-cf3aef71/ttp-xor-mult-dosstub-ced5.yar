rule TTP_XOR_MULT_DOSStub_ced5 {
  strings:
    $key_ced5 = { 9a bd [2] ee a5 [2] a9 a7 [2] ee b6 [2] a0 ba [2] ac b0 [2] bb bb [2] a0 f5 [2] 9d }

  condition:
    any of them
}