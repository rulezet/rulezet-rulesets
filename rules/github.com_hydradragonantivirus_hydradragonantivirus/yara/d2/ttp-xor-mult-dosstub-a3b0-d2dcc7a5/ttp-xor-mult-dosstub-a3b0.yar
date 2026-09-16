rule TTP_XOR_MULT_DOSStub_a3b0 {
  strings:
    $key_a3b0 = { f7 d8 [2] 83 c0 [2] c4 c2 [2] 83 d3 [2] cd df [2] c1 d5 [2] d6 de [2] cd 90 [2] f0 }

  condition:
    any of them
}