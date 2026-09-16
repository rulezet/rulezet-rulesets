rule TTP_XOR_MULT_DOSStub_67d1 {
  strings:
    $key_67d1 = { 33 b9 [2] 47 a1 [2] 00 a3 [2] 47 b2 [2] 09 be [2] 05 b4 [2] 12 bf [2] 09 f1 [2] 34 }

  condition:
    any of them
}