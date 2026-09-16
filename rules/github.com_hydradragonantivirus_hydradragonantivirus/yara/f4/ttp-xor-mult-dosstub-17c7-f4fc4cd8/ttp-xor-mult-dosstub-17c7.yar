rule TTP_XOR_MULT_DOSStub_17c7 {
  strings:
    $key_17c7 = { 43 af [2] 37 b7 [2] 70 b5 [2] 37 a4 [2] 79 a8 [2] 75 a2 [2] 62 a9 [2] 79 e7 [2] 44 }

  condition:
    any of them
}