rule TTP_XOR_MULT_DOSStub_a4ac {
  strings:
    $key_a4ac = { f0 c4 [2] 84 dc [2] c3 de [2] 84 cf [2] ca c3 [2] c6 c9 [2] d1 c2 [2] ca 8c [2] f7 }

  condition:
    any of them
}