rule TTP_XOR_MULT_DOSStub_75b7 {
  strings:
    $key_75b7 = { 21 df [2] 55 c7 [2] 12 c5 [2] 55 d4 [2] 1b d8 [2] 17 d2 [2] 00 d9 [2] 1b 97 [2] 26 }

  condition:
    any of them
}