rule TTP_XOR_MULT_DOSStub_28b0 {
  strings:
    $key_28b0 = { 7c d8 [2] 08 c0 [2] 4f c2 [2] 08 d3 [2] 46 df [2] 4a d5 [2] 5d de [2] 46 90 [2] 7b }

  condition:
    any of them
}