rule TTP_XOR_MULT_DOSStub_42bb {
  strings:
    $key_42bb = { 16 d3 [2] 62 cb [2] 25 c9 [2] 62 d8 [2] 2c d4 [2] 20 de [2] 37 d5 [2] 2c 9b [2] 11 }

  condition:
    any of them
}