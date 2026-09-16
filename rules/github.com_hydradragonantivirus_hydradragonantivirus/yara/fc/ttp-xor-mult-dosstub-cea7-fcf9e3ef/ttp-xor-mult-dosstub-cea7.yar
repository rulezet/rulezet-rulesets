rule TTP_XOR_MULT_DOSStub_cea7 {
  strings:
    $key_cea7 = { 9a cf [2] ee d7 [2] a9 d5 [2] ee c4 [2] a0 c8 [2] ac c2 [2] bb c9 [2] a0 87 [2] 9d }

  condition:
    any of them
}