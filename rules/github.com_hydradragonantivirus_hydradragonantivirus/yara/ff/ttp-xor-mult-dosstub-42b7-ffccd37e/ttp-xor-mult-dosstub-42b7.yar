rule TTP_XOR_MULT_DOSStub_42b7 {
  strings:
    $key_42b7 = { 16 df [2] 62 c7 [2] 25 c5 [2] 62 d4 [2] 2c d8 [2] 20 d2 [2] 37 d9 [2] 2c 97 [2] 11 }

  condition:
    any of them
}