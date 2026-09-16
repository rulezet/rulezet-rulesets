rule TTP_XOR_MULT_DOSStub_a5b0 {
  strings:
    $key_a5b0 = { f1 d8 [2] 85 c0 [2] c2 c2 [2] 85 d3 [2] cb df [2] c7 d5 [2] d0 de [2] cb 90 [2] f6 }

  condition:
    any of them
}