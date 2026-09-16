rule TTP_XOR_MULT_DOSStub_24bb {
  strings:
    $key_24bb = { 70 d3 [2] 04 cb [2] 43 c9 [2] 04 d8 [2] 4a d4 [2] 46 de [2] 51 d5 [2] 4a 9b [2] 77 }

  condition:
    any of them
}