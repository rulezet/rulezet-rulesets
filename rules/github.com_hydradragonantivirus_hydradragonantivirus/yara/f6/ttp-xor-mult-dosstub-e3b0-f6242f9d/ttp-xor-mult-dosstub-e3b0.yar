rule TTP_XOR_MULT_DOSStub_e3b0 {
  strings:
    $key_e3b0 = { b7 d8 [2] c3 c0 [2] 84 c2 [2] c3 d3 [2] 8d df [2] 81 d5 [2] 96 de [2] 8d 90 [2] b0 }

  condition:
    any of them
}