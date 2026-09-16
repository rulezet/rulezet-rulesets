rule TTP_XOR_MULT_DOSStub_46bb {
  strings:
    $key_46bb = { 12 d3 [2] 66 cb [2] 21 c9 [2] 66 d8 [2] 28 d4 [2] 24 de [2] 33 d5 [2] 28 9b [2] 15 }

  condition:
    any of them
}