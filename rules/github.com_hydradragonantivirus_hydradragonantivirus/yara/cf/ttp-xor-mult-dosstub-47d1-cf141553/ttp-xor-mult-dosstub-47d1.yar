rule TTP_XOR_MULT_DOSStub_47d1 {
  strings:
    $key_47d1 = { 13 b9 [2] 67 a1 [2] 20 a3 [2] 67 b2 [2] 29 be [2] 25 b4 [2] 32 bf [2] 29 f1 [2] 14 }

  condition:
    any of them
}