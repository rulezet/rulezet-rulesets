rule TTP_XOR_MULT_DOSStub_41d7 {
  strings:
    $key_41d7 = { 15 bf [2] 61 a7 [2] 26 a5 [2] 61 b4 [2] 2f b8 [2] 23 b2 [2] 34 b9 [2] 2f f7 [2] 12 }

  condition:
    any of them
}