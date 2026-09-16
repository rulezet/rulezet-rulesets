rule TTP_XOR_MULT_DOSStub_22d1 {
  strings:
    $key_22d1 = { 76 b9 [2] 02 a1 [2] 45 a3 [2] 02 b2 [2] 4c be [2] 40 b4 [2] 57 bf [2] 4c f1 [2] 71 }

  condition:
    any of them
}