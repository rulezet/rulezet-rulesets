rule TTP_XOR_MULT_DOSStub_36d1 {
  strings:
    $key_36d1 = { 62 b9 [2] 16 a1 [2] 51 a3 [2] 16 b2 [2] 58 be [2] 54 b4 [2] 43 bf [2] 58 f1 [2] 65 }

  condition:
    any of them
}