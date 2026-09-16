rule TTP_XOR_MULT_DOSStub_74b6 {
  strings:
    $key_74b6 = { 20 de [2] 54 c6 [2] 13 c4 [2] 54 d5 [2] 1a d9 [2] 16 d3 [2] 01 d8 [2] 1a 96 [2] 27 }

  condition:
    any of them
}