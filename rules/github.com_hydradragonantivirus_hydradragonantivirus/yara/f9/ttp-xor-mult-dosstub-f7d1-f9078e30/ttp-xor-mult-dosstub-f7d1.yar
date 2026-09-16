rule TTP_XOR_MULT_DOSStub_f7d1 {
  strings:
    $key_f7d1 = { a3 b9 [2] d7 a1 [2] 90 a3 [2] d7 b2 [2] 99 be [2] 95 b4 [2] 82 bf [2] 99 f1 [2] a4 }

  condition:
    any of them
}