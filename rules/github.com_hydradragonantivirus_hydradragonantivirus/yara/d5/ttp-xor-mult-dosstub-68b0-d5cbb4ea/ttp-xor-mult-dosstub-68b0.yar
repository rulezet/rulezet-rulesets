rule TTP_XOR_MULT_DOSStub_68b0 {
  strings:
    $key_68b0 = { 3c d8 [2] 48 c0 [2] 0f c2 [2] 48 d3 [2] 06 df [2] 0a d5 [2] 1d de [2] 06 90 [2] 3b }

  condition:
    any of them
}