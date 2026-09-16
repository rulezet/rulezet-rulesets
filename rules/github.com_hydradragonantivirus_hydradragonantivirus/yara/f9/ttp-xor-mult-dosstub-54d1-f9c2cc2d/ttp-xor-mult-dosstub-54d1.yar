rule TTP_XOR_MULT_DOSStub_54d1 {
  strings:
    $key_54d1 = { 00 b9 [2] 74 a1 [2] 33 a3 [2] 74 b2 [2] 3a be [2] 36 b4 [2] 21 bf [2] 3a f1 [2] 07 }

  condition:
    any of them
}