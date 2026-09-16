rule TTP_XOR_MULT_DOSStub_e6b6 {
  strings:
    $key_e6b6 = { b2 de [2] c6 c6 [2] 81 c4 [2] c6 d5 [2] 88 d9 [2] 84 d3 [2] 93 d8 [2] 88 96 [2] b5 }

  condition:
    any of them
}