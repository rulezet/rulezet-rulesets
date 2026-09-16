rule TTP_XOR_MULT_DOSStub_1fb0 {
  strings:
    $key_1fb0 = { 4b d8 [2] 3f c0 [2] 78 c2 [2] 3f d3 [2] 71 df [2] 7d d5 [2] 6a de [2] 71 90 [2] 4c }

  condition:
    any of them
}