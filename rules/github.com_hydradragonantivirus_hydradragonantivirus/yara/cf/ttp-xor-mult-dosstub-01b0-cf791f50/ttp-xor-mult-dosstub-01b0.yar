rule TTP_XOR_MULT_DOSStub_01b0 {
  strings:
    $key_01b0 = { 55 d8 [2] 21 c0 [2] 66 c2 [2] 21 d3 [2] 6f df [2] 63 d5 [2] 74 de [2] 6f 90 [2] 52 }

  condition:
    any of them
}