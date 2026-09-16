rule TTP_XOR_MULT_DOSStub_a6a0 {
  strings:
    $key_a6a0 = { f2 c8 [2] 86 d0 [2] c1 d2 [2] 86 c3 [2] c8 cf [2] c4 c5 [2] d3 ce [2] c8 80 [2] f5 }

  condition:
    any of them
}