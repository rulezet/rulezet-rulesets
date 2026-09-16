rule TTP_XOR_MULT_DOSStub_10b6 {
  strings:
    $key_10b6 = { 44 de [2] 30 c6 [2] 77 c4 [2] 30 d5 [2] 7e d9 [2] 72 d3 [2] 65 d8 [2] 7e 96 [2] 43 }

  condition:
    any of them
}