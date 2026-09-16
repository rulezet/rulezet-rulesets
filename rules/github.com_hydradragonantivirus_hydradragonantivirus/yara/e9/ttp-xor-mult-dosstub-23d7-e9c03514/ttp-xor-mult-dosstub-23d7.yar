rule TTP_XOR_MULT_DOSStub_23d7 {
  strings:
    $key_23d7 = { 77 bf [2] 03 a7 [2] 44 a5 [2] 03 b4 [2] 4d b8 [2] 41 b2 [2] 56 b9 [2] 4d f7 [2] 70 }

  condition:
    any of them
}