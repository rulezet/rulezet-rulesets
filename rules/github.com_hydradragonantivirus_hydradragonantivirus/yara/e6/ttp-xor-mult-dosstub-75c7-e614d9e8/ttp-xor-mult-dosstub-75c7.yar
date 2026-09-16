rule TTP_XOR_MULT_DOSStub_75c7 {
  strings:
    $key_75c7 = { 21 af [2] 55 b7 [2] 12 b5 [2] 55 a4 [2] 1b a8 [2] 17 a2 [2] 00 a9 [2] 1b e7 [2] 26 }

  condition:
    any of them
}