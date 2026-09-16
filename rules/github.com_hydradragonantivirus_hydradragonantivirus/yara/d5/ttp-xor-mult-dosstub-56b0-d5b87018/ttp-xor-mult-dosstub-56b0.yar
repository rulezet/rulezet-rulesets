rule TTP_XOR_MULT_DOSStub_56b0 {
  strings:
    $key_56b0 = { 02 d8 [2] 76 c0 [2] 31 c2 [2] 76 d3 [2] 38 df [2] 34 d5 [2] 23 de [2] 38 90 [2] 05 }

  condition:
    any of them
}