rule TTP_XOR_MULT_DOSStub_60d6 {
  strings:
    $key_60d6 = { 34 be [2] 40 a6 [2] 07 a4 [2] 40 b5 [2] 0e b9 [2] 02 b3 [2] 15 b8 [2] 0e f6 [2] 33 }

  condition:
    any of them
}