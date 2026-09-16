rule TTP_XOR_MULT_DOSStub_12bb {
  strings:
    $key_12bb = { 46 d3 [2] 32 cb [2] 75 c9 [2] 32 d8 [2] 7c d4 [2] 70 de [2] 67 d5 [2] 7c 9b [2] 41 }

  condition:
    any of them
}