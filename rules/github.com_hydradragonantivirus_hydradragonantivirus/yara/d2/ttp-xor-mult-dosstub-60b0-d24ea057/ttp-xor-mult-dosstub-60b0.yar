rule TTP_XOR_MULT_DOSStub_60b0 {
  strings:
    $key_60b0 = { 34 d8 [2] 40 c0 [2] 07 c2 [2] 40 d3 [2] 0e df [2] 02 d5 [2] 15 de [2] 0e 90 [2] 33 }

  condition:
    any of them
}