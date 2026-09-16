rule TTP_XOR_MULT_DOSStub_35bb {
  strings:
    $key_35bb = { 61 d3 [2] 15 cb [2] 52 c9 [2] 15 d8 [2] 5b d4 [2] 57 de [2] 40 d5 [2] 5b 9b [2] 66 }

  condition:
    any of them
}