rule TTP_XOR_MULT_DOSStub_ced0 {
  strings:
    $key_ced0 = { 9a b8 [2] ee a0 [2] a9 a2 [2] ee b3 [2] a0 bf [2] ac b5 [2] bb be [2] a0 f0 [2] 9d }

  condition:
    any of them
}