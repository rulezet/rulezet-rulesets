rule TTP_XOR_MULT_DOSStub_caa4 {
  strings:
    $key_caa4 = { 9e cc [2] ea d4 [2] ad d6 [2] ea c7 [2] a4 cb [2] a8 c1 [2] bf ca [2] a4 84 [2] 99 }

  condition:
    any of them
}