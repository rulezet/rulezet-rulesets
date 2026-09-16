rule TTP_XOR_MULT_DOSStub_37d7 {
  strings:
    $key_37d7 = { 63 bf [2] 17 a7 [2] 50 a5 [2] 17 b4 [2] 59 b8 [2] 55 b2 [2] 42 b9 [2] 59 f7 [2] 64 }

  condition:
    any of them
}