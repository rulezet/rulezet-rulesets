rule TTP_XOR_MULT_DOSStub_12d1 {
  strings:
    $key_12d1 = { 46 b9 [2] 32 a1 [2] 75 a3 [2] 32 b2 [2] 7c be [2] 70 b4 [2] 67 bf [2] 7c f1 [2] 41 }

  condition:
    any of them
}