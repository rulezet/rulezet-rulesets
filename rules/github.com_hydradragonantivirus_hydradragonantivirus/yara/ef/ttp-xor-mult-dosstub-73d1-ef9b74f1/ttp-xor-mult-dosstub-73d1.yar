rule TTP_XOR_MULT_DOSStub_73d1 {
  strings:
    $key_73d1 = { 27 b9 [2] 53 a1 [2] 14 a3 [2] 53 b2 [2] 1d be [2] 11 b4 [2] 06 bf [2] 1d f1 [2] 20 }

  condition:
    any of them
}