rule TTP_XOR_MULT_DOSStub_52d1 {
  strings:
    $key_52d1 = { 06 b9 [2] 72 a1 [2] 35 a3 [2] 72 b2 [2] 3c be [2] 30 b4 [2] 27 bf [2] 3c f1 [2] 01 }

  condition:
    any of them
}