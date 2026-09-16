rule TTP_XOR_MULT_DOSStub_32d1 {
  strings:
    $key_32d1 = { 66 b9 [2] 12 a1 [2] 55 a3 [2] 12 b2 [2] 5c be [2] 50 b4 [2] 47 bf [2] 5c f1 [2] 61 }

  condition:
    any of them
}