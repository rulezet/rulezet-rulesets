rule TTP_XOR_MULT_DOSStub_62d7 {
  strings:
    $key_62d7 = { 36 bf [2] 42 a7 [2] 05 a5 [2] 42 b4 [2] 0c b8 [2] 00 b2 [2] 17 b9 [2] 0c f7 [2] 31 }

  condition:
    any of them
}