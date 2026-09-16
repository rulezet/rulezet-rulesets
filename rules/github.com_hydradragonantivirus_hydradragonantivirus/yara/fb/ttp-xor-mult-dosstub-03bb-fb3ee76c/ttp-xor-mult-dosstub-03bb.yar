rule TTP_XOR_MULT_DOSStub_03bb {
  strings:
    $key_03bb = { 57 d3 [2] 23 cb [2] 64 c9 [2] 23 d8 [2] 6d d4 [2] 61 de [2] 76 d5 [2] 6d 9b [2] 50 }

  condition:
    any of them
}