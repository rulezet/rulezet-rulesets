rule TTP_XOR_MULT_DOSStub_73bb {
  strings:
    $key_73bb = { 27 d3 [2] 53 cb [2] 14 c9 [2] 53 d8 [2] 1d d4 [2] 11 de [2] 06 d5 [2] 1d 9b [2] 20 }

  condition:
    any of them
}