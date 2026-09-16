rule TTP_XOR_MULT_DOSStub_4bb0 {
  strings:
    $key_4bb0 = { 1f d8 [2] 6b c0 [2] 2c c2 [2] 6b d3 [2] 25 df [2] 29 d5 [2] 3e de [2] 25 90 [2] 18 }

  condition:
    any of them
}