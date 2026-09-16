rule TTP_XOR_MULT_DOSStub_78d1 {
  strings:
    $key_78d1 = { 2c b9 [2] 58 a1 [2] 1f a3 [2] 58 b2 [2] 16 be [2] 1a b4 [2] 0d bf [2] 16 f1 [2] 2b }

  condition:
    any of them
}