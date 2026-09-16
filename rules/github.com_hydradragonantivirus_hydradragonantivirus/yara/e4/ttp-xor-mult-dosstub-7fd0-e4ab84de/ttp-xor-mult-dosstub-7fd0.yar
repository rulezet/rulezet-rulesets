rule TTP_XOR_MULT_DOSStub_7fd0 {
  strings:
    $key_7fd0 = { 2b b8 [2] 5f a0 [2] 18 a2 [2] 5f b3 [2] 11 bf [2] 1d b5 [2] 0a be [2] 11 f0 [2] 2c }

  condition:
    any of them
}