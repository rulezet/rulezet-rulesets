rule TTP_XOR_MULT_DOSStub_22d7 {
  strings:
    $key_22d7 = { 76 bf [2] 02 a7 [2] 45 a5 [2] 02 b4 [2] 4c b8 [2] 40 b2 [2] 57 b9 [2] 4c f7 [2] 71 }

  condition:
    any of them
}