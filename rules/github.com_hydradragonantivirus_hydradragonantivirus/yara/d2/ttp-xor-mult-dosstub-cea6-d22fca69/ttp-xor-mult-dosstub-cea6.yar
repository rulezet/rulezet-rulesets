rule TTP_XOR_MULT_DOSStub_cea6 {
  strings:
    $key_cea6 = { 9a ce [2] ee d6 [2] a9 d4 [2] ee c5 [2] a0 c9 [2] ac c3 [2] bb c8 [2] a0 86 [2] 9d }

  condition:
    any of them
}