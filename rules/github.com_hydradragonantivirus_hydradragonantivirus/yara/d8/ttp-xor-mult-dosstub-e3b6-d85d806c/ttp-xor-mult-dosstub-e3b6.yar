rule TTP_XOR_MULT_DOSStub_e3b6 {
  strings:
    $key_e3b6 = { b7 de [2] c3 c6 [2] 84 c4 [2] c3 d5 [2] 8d d9 [2] 81 d3 [2] 96 d8 [2] 8d 96 [2] b0 }

  condition:
    any of them
}