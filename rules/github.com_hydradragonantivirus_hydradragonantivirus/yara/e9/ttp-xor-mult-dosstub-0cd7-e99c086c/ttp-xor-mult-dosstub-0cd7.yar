rule TTP_XOR_MULT_DOSStub_0cd7 {
  strings:
    $key_0cd7 = { 58 bf [2] 2c a7 [2] 6b a5 [2] 2c b4 [2] 62 b8 [2] 6e b2 [2] 79 b9 [2] 62 f7 [2] 5f }

  condition:
    any of them
}