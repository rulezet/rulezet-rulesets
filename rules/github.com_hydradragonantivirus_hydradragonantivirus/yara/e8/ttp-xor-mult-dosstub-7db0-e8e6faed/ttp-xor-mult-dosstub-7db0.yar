rule TTP_XOR_MULT_DOSStub_7db0 {
  strings:
    $key_7db0 = { 29 d8 [2] 5d c0 [2] 1a c2 [2] 5d d3 [2] 13 df [2] 1f d5 [2] 08 de [2] 13 90 [2] 2e }

  condition:
    any of them
}