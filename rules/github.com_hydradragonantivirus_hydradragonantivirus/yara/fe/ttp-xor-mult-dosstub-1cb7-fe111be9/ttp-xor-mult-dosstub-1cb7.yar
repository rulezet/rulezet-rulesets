rule TTP_XOR_MULT_DOSStub_1cb7 {
  strings:
    $key_1cb7 = { 48 df [2] 3c c7 [2] 7b c5 [2] 3c d4 [2] 72 d8 [2] 7e d2 [2] 69 d9 [2] 72 97 [2] 4f }

  condition:
    any of them
}