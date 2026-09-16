rule TTP_XOR_MULT_DOSStub_27b7 {
  strings:
    $key_27b7 = { 73 df [2] 07 c7 [2] 40 c5 [2] 07 d4 [2] 49 d8 [2] 45 d2 [2] 52 d9 [2] 49 97 [2] 74 }

  condition:
    any of them
}