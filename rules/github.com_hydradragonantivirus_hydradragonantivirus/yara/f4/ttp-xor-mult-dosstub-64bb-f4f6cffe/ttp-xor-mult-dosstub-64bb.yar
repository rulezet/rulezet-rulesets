rule TTP_XOR_MULT_DOSStub_64bb {
  strings:
    $key_64bb = { 30 d3 [2] 44 cb [2] 03 c9 [2] 44 d8 [2] 0a d4 [2] 06 de [2] 11 d5 [2] 0a 9b [2] 37 }

  condition:
    any of them
}