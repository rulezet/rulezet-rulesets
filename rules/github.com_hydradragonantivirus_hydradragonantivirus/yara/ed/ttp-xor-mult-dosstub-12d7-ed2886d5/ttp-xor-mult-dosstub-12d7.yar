rule TTP_XOR_MULT_DOSStub_12d7 {
  strings:
    $key_12d7 = { 46 bf [2] 32 a7 [2] 75 a5 [2] 32 b4 [2] 7c b8 [2] 70 b2 [2] 67 b9 [2] 7c f7 [2] 41 }

  condition:
    any of them
}