rule TTP_XOR_MULT_DOSStub_26b7 {
  strings:
    $key_26b7 = { 72 df [2] 06 c7 [2] 41 c5 [2] 06 d4 [2] 48 d8 [2] 44 d2 [2] 53 d9 [2] 48 97 [2] 75 }

  condition:
    any of them
}