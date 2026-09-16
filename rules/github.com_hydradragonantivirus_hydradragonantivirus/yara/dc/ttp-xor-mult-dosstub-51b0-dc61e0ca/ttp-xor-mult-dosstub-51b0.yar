rule TTP_XOR_MULT_DOSStub_51b0 {
  strings:
    $key_51b0 = { 05 d8 [2] 71 c0 [2] 36 c2 [2] 71 d3 [2] 3f df [2] 33 d5 [2] 24 de [2] 3f 90 [2] 02 }

  condition:
    any of them
}