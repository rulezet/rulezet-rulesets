rule TTP_XOR_MULT_DOSStub_fdd1 {
  strings:
    $key_fdd1 = { a9 b9 [2] dd a1 [2] 9a a3 [2] dd b2 [2] 93 be [2] 9f b4 [2] 88 bf [2] 93 f1 [2] ae }

  condition:
    any of them
}