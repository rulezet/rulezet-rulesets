rule TTP_XOR_MULT_DOSStub_45bb {
  strings:
    $key_45bb = { 11 d3 [2] 65 cb [2] 22 c9 [2] 65 d8 [2] 2b d4 [2] 27 de [2] 30 d5 [2] 2b 9b [2] 16 }

  condition:
    any of them
}