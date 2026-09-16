rule TTP_XOR_MULT_DOSStub_7fd7 {
  strings:
    $key_7fd7 = { 2b bf [2] 5f a7 [2] 18 a5 [2] 5f b4 [2] 11 b8 [2] 1d b2 [2] 0a b9 [2] 11 f7 [2] 2c }

  condition:
    any of them
}