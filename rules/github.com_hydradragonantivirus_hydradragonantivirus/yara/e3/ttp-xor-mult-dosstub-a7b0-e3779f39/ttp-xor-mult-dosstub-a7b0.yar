rule TTP_XOR_MULT_DOSStub_a7b0 {
  strings:
    $key_a7b0 = { f3 d8 [2] 87 c0 [2] c0 c2 [2] 87 d3 [2] c9 df [2] c5 d5 [2] d2 de [2] c9 90 [2] f4 }

  condition:
    any of them
}