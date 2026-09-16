rule TTP_XOR_MULT_DOSStub_04d7 {
  strings:
    $key_04d7 = { 50 bf [2] 24 a7 [2] 63 a5 [2] 24 b4 [2] 6a b8 [2] 66 b2 [2] 71 b9 [2] 6a f7 [2] 57 }

  condition:
    any of them
}