rule TTP_XOR_MULT_DOSStub_51b7 {
  strings:
    $key_51b7 = { 05 df [2] 71 c7 [2] 36 c5 [2] 71 d4 [2] 3f d8 [2] 33 d2 [2] 24 d9 [2] 3f 97 [2] 02 }

  condition:
    any of them
}