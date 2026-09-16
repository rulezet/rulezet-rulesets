rule TTP_XOR_MULT_DOSStub_59d1 {
  strings:
    $key_59d1 = { 0d b9 [2] 79 a1 [2] 3e a3 [2] 79 b2 [2] 37 be [2] 3b b4 [2] 2c bf [2] 37 f1 [2] 0a }

  condition:
    any of them
}