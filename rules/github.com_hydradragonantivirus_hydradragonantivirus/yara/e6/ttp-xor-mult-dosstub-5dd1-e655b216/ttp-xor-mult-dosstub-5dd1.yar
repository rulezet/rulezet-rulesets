rule TTP_XOR_MULT_DOSStub_5dd1 {
  strings:
    $key_5dd1 = { 09 b9 [2] 7d a1 [2] 3a a3 [2] 7d b2 [2] 33 be [2] 3f b4 [2] 28 bf [2] 33 f1 [2] 0e }

  condition:
    any of them
}