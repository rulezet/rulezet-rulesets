rule TTP_XOR_MULT_DOSStub_7fb0 {
  strings:
    $key_7fb0 = { 2b d8 [2] 5f c0 [2] 18 c2 [2] 5f d3 [2] 11 df [2] 1d d5 [2] 0a de [2] 11 90 [2] 2c }

  condition:
    any of them
}