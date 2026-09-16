rule TTP_XOR_MULT_DOSStub_a645 {
  strings:
    $key_a645 = { f2 2d [2] 86 35 [2] c1 37 [2] 86 26 [2] c8 2a [2] c4 20 [2] d3 2b [2] c8 65 [2] f5 }

  condition:
    any of them
}