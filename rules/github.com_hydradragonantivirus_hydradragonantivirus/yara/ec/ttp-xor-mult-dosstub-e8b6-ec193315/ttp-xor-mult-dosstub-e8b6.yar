rule TTP_XOR_MULT_DOSStub_e8b6 {
  strings:
    $key_e8b6 = { bc de [2] c8 c6 [2] 8f c4 [2] c8 d5 [2] 86 d9 [2] 8a d3 [2] 9d d8 [2] 86 96 [2] bb }

  condition:
    any of them
}