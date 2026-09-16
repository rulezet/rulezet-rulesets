rule TTP_XOR_MULT_DOSStub_60b7 {
  strings:
    $key_60b7 = { 34 df [2] 40 c7 [2] 07 c5 [2] 40 d4 [2] 0e d8 [2] 02 d2 [2] 15 d9 [2] 0e 97 [2] 33 }

  condition:
    any of them
}