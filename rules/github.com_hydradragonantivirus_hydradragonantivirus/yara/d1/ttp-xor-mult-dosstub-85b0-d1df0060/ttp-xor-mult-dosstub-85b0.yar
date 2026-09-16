rule TTP_XOR_MULT_DOSStub_85b0 {
  strings:
    $key_85b0 = { d1 d8 [2] a5 c0 [2] e2 c2 [2] a5 d3 [2] eb df [2] e7 d5 [2] f0 de [2] eb 90 [2] d6 }

  condition:
    any of them
}