rule TTP_XOR_MULT_DOSStub_47b0 {
  strings:
    $key_47b0 = { 13 d8 [2] 67 c0 [2] 20 c2 [2] 67 d3 [2] 29 df [2] 25 d5 [2] 32 de [2] 29 90 [2] 14 }

  condition:
    any of them
}