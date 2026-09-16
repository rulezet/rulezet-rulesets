rule TTP_XOR_MULT_DOSStub_4eb0 {
  strings:
    $key_4eb0 = { 1a d8 [2] 6e c0 [2] 29 c2 [2] 6e d3 [2] 20 df [2] 2c d5 [2] 3b de [2] 20 90 [2] 1d }

  condition:
    any of them
}