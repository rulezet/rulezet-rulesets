rule TTP_XOR_MULT_DOSStub_ecb1 {
  strings:
    $key_ecb1 = { b8 d9 [2] cc c1 [2] 8b c3 [2] cc d2 [2] 82 de [2] 8e d4 [2] 99 df [2] 82 91 [2] bf }

  condition:
    any of them
}