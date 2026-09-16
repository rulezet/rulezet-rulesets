rule TTP_XOR_MULT_DOSStub_15bb {
  strings:
    $key_15bb = { 41 d3 [2] 35 cb [2] 72 c9 [2] 35 d8 [2] 7b d4 [2] 77 de [2] 60 d5 [2] 7b 9b [2] 46 }

  condition:
    any of them
}