rule TTP_XOR_MULT_DOSStub_31b7 {
  strings:
    $key_31b7 = { 65 df [2] 11 c7 [2] 56 c5 [2] 11 d4 [2] 5f d8 [2] 53 d2 [2] 44 d9 [2] 5f 97 [2] 62 }

  condition:
    any of them
}