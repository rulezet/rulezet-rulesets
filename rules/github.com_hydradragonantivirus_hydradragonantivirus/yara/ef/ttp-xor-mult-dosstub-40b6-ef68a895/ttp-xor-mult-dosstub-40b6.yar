rule TTP_XOR_MULT_DOSStub_40b6 {
  strings:
    $key_40b6 = { 14 de [2] 60 c6 [2] 27 c4 [2] 60 d5 [2] 2e d9 [2] 22 d3 [2] 35 d8 [2] 2e 96 [2] 13 }

  condition:
    any of them
}