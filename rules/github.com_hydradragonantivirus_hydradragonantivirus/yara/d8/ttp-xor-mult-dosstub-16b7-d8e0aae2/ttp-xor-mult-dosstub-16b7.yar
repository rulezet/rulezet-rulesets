rule TTP_XOR_MULT_DOSStub_16b7 {
  strings:
    $key_16b7 = { 42 df [2] 36 c7 [2] 71 c5 [2] 36 d4 [2] 78 d8 [2] 74 d2 [2] 63 d9 [2] 78 97 [2] 45 }

  condition:
    any of them
}