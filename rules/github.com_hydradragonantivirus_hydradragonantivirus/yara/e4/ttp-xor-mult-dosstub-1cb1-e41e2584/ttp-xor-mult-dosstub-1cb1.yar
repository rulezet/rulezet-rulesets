rule TTP_XOR_MULT_DOSStub_1cb1 {
  strings:
    $key_1cb1 = { 48 d9 [2] 3c c1 [2] 7b c3 [2] 3c d2 [2] 72 de [2] 7e d4 [2] 69 df [2] 72 91 [2] 4f }

  condition:
    any of them
}