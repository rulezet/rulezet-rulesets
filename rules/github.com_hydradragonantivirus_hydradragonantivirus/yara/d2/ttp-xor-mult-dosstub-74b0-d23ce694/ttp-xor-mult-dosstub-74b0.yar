rule TTP_XOR_MULT_DOSStub_74b0 {
  strings:
    $key_74b0 = { 20 d8 [2] 54 c0 [2] 13 c2 [2] 54 d3 [2] 1a df [2] 16 d5 [2] 01 de [2] 1a 90 [2] 27 }

  condition:
    any of them
}