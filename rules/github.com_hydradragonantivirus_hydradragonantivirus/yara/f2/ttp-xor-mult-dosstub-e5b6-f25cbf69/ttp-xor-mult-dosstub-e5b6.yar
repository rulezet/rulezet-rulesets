rule TTP_XOR_MULT_DOSStub_e5b6 {
  strings:
    $key_e5b6 = { b1 de [2] c5 c6 [2] 82 c4 [2] c5 d5 [2] 8b d9 [2] 87 d3 [2] 90 d8 [2] 8b 96 [2] b6 }

  condition:
    any of them
}