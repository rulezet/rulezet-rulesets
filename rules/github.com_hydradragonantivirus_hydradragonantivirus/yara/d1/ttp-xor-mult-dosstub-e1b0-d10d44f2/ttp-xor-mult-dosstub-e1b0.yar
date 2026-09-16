rule TTP_XOR_MULT_DOSStub_e1b0 {
  strings:
    $key_e1b0 = { b5 d8 [2] c1 c0 [2] 86 c2 [2] c1 d3 [2] 8f df [2] 83 d5 [2] 94 de [2] 8f 90 [2] b2 }

  condition:
    any of them
}