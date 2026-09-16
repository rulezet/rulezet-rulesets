rule TTP_XOR_MULT_DOSStub_53bb {
  strings:
    $key_53bb = { 07 d3 [2] 73 cb [2] 34 c9 [2] 73 d8 [2] 3d d4 [2] 31 de [2] 26 d5 [2] 3d 9b [2] 00 }

  condition:
    any of them
}