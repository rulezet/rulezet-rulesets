rule TTP_XOR_MULT_DOSStub_d5b0 {
  strings:
    $key_d5b0 = { 81 d8 [2] f5 c0 [2] b2 c2 [2] f5 d3 [2] bb df [2] b7 d5 [2] a0 de [2] bb 90 [2] 86 }

  condition:
    any of them
}