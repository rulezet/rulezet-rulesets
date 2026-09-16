rule TTP_XOR_MULT_DOSStub_76b0 {
  strings:
    $key_76b0 = { 22 d8 [2] 56 c0 [2] 11 c2 [2] 56 d3 [2] 18 df [2] 14 d5 [2] 03 de [2] 18 90 [2] 25 }

  condition:
    any of them
}