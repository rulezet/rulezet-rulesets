rule TTP_XOR_MULT_DOSStub_7cb7 {
  strings:
    $key_7cb7 = { 28 df [2] 5c c7 [2] 1b c5 [2] 5c d4 [2] 12 d8 [2] 1e d2 [2] 09 d9 [2] 12 97 [2] 2f }

  condition:
    any of them
}