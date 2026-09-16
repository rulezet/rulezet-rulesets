rule TTP_XOR_MULT_DOSStub_62d1 {
  strings:
    $key_62d1 = { 36 b9 [2] 42 a1 [2] 05 a3 [2] 42 b2 [2] 0c be [2] 00 b4 [2] 17 bf [2] 0c f1 [2] 31 }

  condition:
    any of them
}