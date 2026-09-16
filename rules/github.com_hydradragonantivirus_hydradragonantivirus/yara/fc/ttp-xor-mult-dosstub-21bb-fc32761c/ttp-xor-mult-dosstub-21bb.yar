rule TTP_XOR_MULT_DOSStub_21bb {
  strings:
    $key_21bb = { 75 d3 [2] 01 cb [2] 46 c9 [2] 01 d8 [2] 4f d4 [2] 43 de [2] 54 d5 [2] 4f 9b [2] 72 }

  condition:
    any of them
}