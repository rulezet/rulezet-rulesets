rule TTP_XOR_MULT_DOSStub_53b6 {
  strings:
    $key_53b6 = { 07 de [2] 73 c6 [2] 34 c4 [2] 73 d5 [2] 3d d9 [2] 31 d3 [2] 26 d8 [2] 3d 96 [2] 00 }

  condition:
    any of them
}