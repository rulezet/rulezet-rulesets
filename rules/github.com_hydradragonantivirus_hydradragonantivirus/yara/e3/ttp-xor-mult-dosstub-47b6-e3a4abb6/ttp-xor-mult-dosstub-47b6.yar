rule TTP_XOR_MULT_DOSStub_47b6 {
  strings:
    $key_47b6 = { 13 de [2] 67 c6 [2] 20 c4 [2] 67 d5 [2] 29 d9 [2] 25 d3 [2] 32 d8 [2] 29 96 [2] 14 }

  condition:
    any of them
}