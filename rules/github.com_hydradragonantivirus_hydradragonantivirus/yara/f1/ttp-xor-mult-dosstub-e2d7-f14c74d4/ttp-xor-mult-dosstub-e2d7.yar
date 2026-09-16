rule TTP_XOR_MULT_DOSStub_e2d7 {
  strings:
    $key_e2d7 = { b6 bf [2] c2 a7 [2] 85 a5 [2] c2 b4 [2] 8c b8 [2] 80 b2 [2] 97 b9 [2] 8c f7 [2] b1 }

  condition:
    any of them
}