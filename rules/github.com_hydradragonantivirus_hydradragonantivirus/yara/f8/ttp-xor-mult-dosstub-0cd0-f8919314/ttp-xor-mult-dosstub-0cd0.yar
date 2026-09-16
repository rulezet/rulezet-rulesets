rule TTP_XOR_MULT_DOSStub_0cd0 {
  strings:
    $key_0cd0 = { 58 b8 [2] 2c a0 [2] 6b a2 [2] 2c b3 [2] 62 bf [2] 6e b5 [2] 79 be [2] 62 f0 [2] 5f }

  condition:
    any of them
}