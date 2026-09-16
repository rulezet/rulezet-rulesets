rule TTP_XOR_MULT_DOSStub_51bb {
  strings:
    $key_51bb = { 05 d3 [2] 71 cb [2] 36 c9 [2] 71 d8 [2] 3f d4 [2] 33 de [2] 24 d5 [2] 3f 9b [2] 02 }

  condition:
    any of them
}