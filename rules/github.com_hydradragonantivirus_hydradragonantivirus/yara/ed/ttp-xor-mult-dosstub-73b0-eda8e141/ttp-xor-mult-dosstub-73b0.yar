rule TTP_XOR_MULT_DOSStub_73b0 {
  strings:
    $key_73b0 = { 27 d8 [2] 53 c0 [2] 14 c2 [2] 53 d3 [2] 1d df [2] 11 d5 [2] 06 de [2] 1d 90 [2] 20 }

  condition:
    any of them
}