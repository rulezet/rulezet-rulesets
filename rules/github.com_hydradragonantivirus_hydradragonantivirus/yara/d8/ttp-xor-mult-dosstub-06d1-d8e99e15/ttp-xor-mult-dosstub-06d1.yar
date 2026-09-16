rule TTP_XOR_MULT_DOSStub_06d1 {
  strings:
    $key_06d1 = { 52 b9 [2] 26 a1 [2] 61 a3 [2] 26 b2 [2] 68 be [2] 64 b4 [2] 73 bf [2] 68 f1 [2] 55 }

  condition:
    any of them
}