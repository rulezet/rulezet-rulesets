rule TTP_XOR_MULT_DOSStub_a7ac {
  strings:
    $key_a7ac = { f3 c4 [2] 87 dc [2] c0 de [2] 87 cf [2] c9 c3 [2] c5 c9 [2] d2 c2 [2] c9 8c [2] f4 }

  condition:
    any of them
}