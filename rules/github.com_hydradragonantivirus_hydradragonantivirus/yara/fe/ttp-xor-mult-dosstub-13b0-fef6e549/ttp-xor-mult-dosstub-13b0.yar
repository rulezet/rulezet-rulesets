rule TTP_XOR_MULT_DOSStub_13b0 {
  strings:
    $key_13b0 = { 47 d8 [2] 33 c0 [2] 74 c2 [2] 33 d3 [2] 7d df [2] 71 d5 [2] 66 de [2] 7d 90 [2] 40 }

  condition:
    any of them
}