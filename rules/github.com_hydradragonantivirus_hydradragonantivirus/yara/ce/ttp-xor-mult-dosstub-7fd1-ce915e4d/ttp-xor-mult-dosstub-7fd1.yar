rule TTP_XOR_MULT_DOSStub_7fd1 {
  strings:
    $key_7fd1 = { 2b b9 [2] 5f a1 [2] 18 a3 [2] 5f b2 [2] 11 be [2] 1d b4 [2] 0a bf [2] 11 f1 [2] 2c }

  condition:
    any of them
}