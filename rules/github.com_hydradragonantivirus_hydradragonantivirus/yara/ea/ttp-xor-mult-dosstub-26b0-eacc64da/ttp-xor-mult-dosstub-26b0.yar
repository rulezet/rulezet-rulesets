rule TTP_XOR_MULT_DOSStub_26b0 {
  strings:
    $key_26b0 = { 72 d8 [2] 06 c0 [2] 41 c2 [2] 06 d3 [2] 48 df [2] 44 d5 [2] 53 de [2] 48 90 [2] 75 }

  condition:
    any of them
}