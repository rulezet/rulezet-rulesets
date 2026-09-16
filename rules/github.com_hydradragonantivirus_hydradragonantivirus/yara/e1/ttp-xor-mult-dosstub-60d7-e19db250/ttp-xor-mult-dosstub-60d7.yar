rule TTP_XOR_MULT_DOSStub_60d7 {
  strings:
    $key_60d7 = { 34 bf [2] 40 a7 [2] 07 a5 [2] 40 b4 [2] 0e b8 [2] 02 b2 [2] 15 b9 [2] 0e f7 [2] 33 }

  condition:
    any of them
}