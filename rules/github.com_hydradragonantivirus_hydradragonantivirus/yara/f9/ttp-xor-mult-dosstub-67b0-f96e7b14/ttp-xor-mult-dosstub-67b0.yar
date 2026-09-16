rule TTP_XOR_MULT_DOSStub_67b0 {
  strings:
    $key_67b0 = { 33 d8 [2] 47 c0 [2] 00 c2 [2] 47 d3 [2] 09 df [2] 05 d5 [2] 12 de [2] 09 90 [2] 34 }

  condition:
    any of them
}