rule TTP_XOR_MULT_DOSStub_03b0 {
  strings:
    $key_03b0 = { 57 d8 [2] 23 c0 [2] 64 c2 [2] 23 d3 [2] 6d df [2] 61 d5 [2] 76 de [2] 6d 90 [2] 50 }

  condition:
    any of them
}