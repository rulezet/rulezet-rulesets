rule TTP_XOR_MULT_DOSStub_76d1 {
  strings:
    $key_76d1 = { 22 b9 [2] 56 a1 [2] 11 a3 [2] 56 b2 [2] 18 be [2] 14 b4 [2] 03 bf [2] 18 f1 [2] 25 }

  condition:
    any of them
}