rule TTP_XOR_MULT_DOSStub_ecb0 {
  strings:
    $key_ecb0 = { b8 d8 [2] cc c0 [2] 8b c2 [2] cc d3 [2] 82 df [2] 8e d5 [2] 99 de [2] 82 90 [2] bf }

  condition:
    any of them
}