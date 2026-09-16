rule TTP_XOR_MULT_DOSStub_17c6 {
  strings:
    $key_17c6 = { 43 ae [2] 37 b6 [2] 70 b4 [2] 37 a5 [2] 79 a9 [2] 75 a3 [2] 62 a8 [2] 79 e6 [2] 44 }

  condition:
    any of them
}