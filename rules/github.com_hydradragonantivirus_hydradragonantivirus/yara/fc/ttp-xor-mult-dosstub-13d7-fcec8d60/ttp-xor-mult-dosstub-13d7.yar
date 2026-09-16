rule TTP_XOR_MULT_DOSStub_13d7 {
  strings:
    $key_13d7 = { 47 bf [2] 33 a7 [2] 74 a5 [2] 33 b4 [2] 7d b8 [2] 71 b2 [2] 66 b9 [2] 7d f7 [2] 40 }

  condition:
    any of them
}