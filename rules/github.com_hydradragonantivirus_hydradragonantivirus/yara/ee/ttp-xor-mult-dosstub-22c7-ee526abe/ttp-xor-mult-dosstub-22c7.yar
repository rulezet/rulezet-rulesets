rule TTP_XOR_MULT_DOSStub_22c7 {
  strings:
    $key_22c7 = { 76 af [2] 02 b7 [2] 45 b5 [2] 02 a4 [2] 4c a8 [2] 40 a2 [2] 57 a9 [2] 4c e7 [2] 71 }

  condition:
    any of them
}