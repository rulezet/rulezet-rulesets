rule TTP_XOR_MULT_DOSStub_60b6 {
  strings:
    $key_60b6 = { 34 de [2] 40 c6 [2] 07 c4 [2] 40 d5 [2] 0e d9 [2] 02 d3 [2] 15 d8 [2] 0e 96 [2] 33 }

  condition:
    any of them
}