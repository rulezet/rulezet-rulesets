rule TTP_XOR_MULT_DOSStub_5eb0 {
  strings:
    $key_5eb0 = { 0a d8 [2] 7e c0 [2] 39 c2 [2] 7e d3 [2] 30 df [2] 3c d5 [2] 2b de [2] 30 90 [2] 0d }

  condition:
    any of them
}