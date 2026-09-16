rule TTP_XOR_MULT_DOSStub_02d1 {
  strings:
    $key_02d1 = { 56 b9 [2] 22 a1 [2] 65 a3 [2] 22 b2 [2] 6c be [2] 60 b4 [2] 77 bf [2] 6c f1 [2] 51 }

  condition:
    any of them
}