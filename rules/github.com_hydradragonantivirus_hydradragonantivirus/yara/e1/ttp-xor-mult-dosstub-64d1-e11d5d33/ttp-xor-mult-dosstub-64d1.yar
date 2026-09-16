rule TTP_XOR_MULT_DOSStub_64d1 {
  strings:
    $key_64d1 = { 30 b9 [2] 44 a1 [2] 03 a3 [2] 44 b2 [2] 0a be [2] 06 b4 [2] 11 bf [2] 0a f1 [2] 37 }

  condition:
    any of them
}