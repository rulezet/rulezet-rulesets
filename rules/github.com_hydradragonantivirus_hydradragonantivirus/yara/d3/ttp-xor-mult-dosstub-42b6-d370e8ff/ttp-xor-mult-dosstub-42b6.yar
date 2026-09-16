rule TTP_XOR_MULT_DOSStub_42b6 {
  strings:
    $key_42b6 = { 16 de [2] 62 c6 [2] 25 c4 [2] 62 d5 [2] 2c d9 [2] 20 d3 [2] 37 d8 [2] 2c 96 [2] 11 }

  condition:
    any of them
}