rule TTP_XOR_MULT_DOSStub_59b0 {
  strings:
    $key_59b0 = { 0d d8 [2] 79 c0 [2] 3e c2 [2] 79 d3 [2] 37 df [2] 3b d5 [2] 2c de [2] 37 90 [2] 0a }

  condition:
    any of them
}