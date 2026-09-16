rule TTP_XOR_MULT_DOSStub_43b0 {
  strings:
    $key_43b0 = { 17 d8 [2] 63 c0 [2] 24 c2 [2] 63 d3 [2] 2d df [2] 21 d5 [2] 36 de [2] 2d 90 [2] 10 }

  condition:
    any of them
}