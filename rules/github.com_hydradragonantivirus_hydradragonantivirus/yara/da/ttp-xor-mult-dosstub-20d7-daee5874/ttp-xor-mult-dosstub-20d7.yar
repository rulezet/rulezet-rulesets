rule TTP_XOR_MULT_DOSStub_20d7 {
  strings:
    $key_20d7 = { 74 bf [2] 00 a7 [2] 47 a5 [2] 00 b4 [2] 4e b8 [2] 42 b2 [2] 55 b9 [2] 4e f7 [2] 73 }

  condition:
    any of them
}