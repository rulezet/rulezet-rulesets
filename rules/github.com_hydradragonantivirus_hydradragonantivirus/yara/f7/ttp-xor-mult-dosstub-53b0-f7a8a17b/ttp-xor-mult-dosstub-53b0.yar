rule TTP_XOR_MULT_DOSStub_53b0 {
  strings:
    $key_53b0 = { 07 d8 [2] 73 c0 [2] 34 c2 [2] 73 d3 [2] 3d df [2] 31 d5 [2] 26 de [2] 3d 90 [2] 00 }

  condition:
    any of them
}