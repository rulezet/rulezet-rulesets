rule TTP_XOR_MULT_DOSStub_97b0 {
  strings:
    $key_97b0 = { c3 d8 [2] b7 c0 [2] f0 c2 [2] b7 d3 [2] f9 df [2] f5 d5 [2] e2 de [2] f9 90 [2] c4 }

  condition:
    any of them
}