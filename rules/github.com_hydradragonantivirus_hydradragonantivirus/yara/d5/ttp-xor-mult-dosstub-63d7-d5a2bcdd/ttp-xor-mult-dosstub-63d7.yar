rule TTP_XOR_MULT_DOSStub_63d7 {
  strings:
    $key_63d7 = { 37 bf [2] 43 a7 [2] 04 a5 [2] 43 b4 [2] 0d b8 [2] 01 b2 [2] 16 b9 [2] 0d f7 [2] 30 }

  condition:
    any of them
}