rule TTP_XOR_MULT_DOSStub_a3b6 {
  strings:
    $key_a3b6 = { f7 de [2] 83 c6 [2] c4 c4 [2] 83 d5 [2] cd d9 [2] c1 d3 [2] d6 d8 [2] cd 96 [2] f0 }

  condition:
    any of them
}