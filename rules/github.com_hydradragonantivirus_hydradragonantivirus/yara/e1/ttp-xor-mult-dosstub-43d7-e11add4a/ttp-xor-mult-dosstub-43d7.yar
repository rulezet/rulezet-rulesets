rule TTP_XOR_MULT_DOSStub_43d7 {
  strings:
    $key_43d7 = { 17 bf [2] 63 a7 [2] 24 a5 [2] 63 b4 [2] 2d b8 [2] 21 b2 [2] 36 b9 [2] 2d f7 [2] 10 }

  condition:
    any of them
}