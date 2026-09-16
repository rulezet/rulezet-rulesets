rule TTP_XOR_MULT_DOSStub_45b7 {
  strings:
    $key_45b7 = { 11 df [2] 65 c7 [2] 22 c5 [2] 65 d4 [2] 2b d8 [2] 27 d2 [2] 30 d9 [2] 2b 97 [2] 16 }

  condition:
    any of them
}