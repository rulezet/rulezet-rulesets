rule TTP_XOR_MULT_DOSStub_38b0 {
  strings:
    $key_38b0 = { 6c d8 [2] 18 c0 [2] 5f c2 [2] 18 d3 [2] 56 df [2] 5a d5 [2] 4d de [2] 56 90 [2] 6b }

  condition:
    any of them
}