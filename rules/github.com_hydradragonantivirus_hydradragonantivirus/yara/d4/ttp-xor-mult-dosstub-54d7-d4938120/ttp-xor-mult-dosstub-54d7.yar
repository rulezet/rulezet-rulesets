rule TTP_XOR_MULT_DOSStub_54d7 {
  strings:
    $key_54d7 = { 00 bf [2] 74 a7 [2] 33 a5 [2] 74 b4 [2] 3a b8 [2] 36 b2 [2] 21 b9 [2] 3a f7 [2] 07 }

  condition:
    any of them
}