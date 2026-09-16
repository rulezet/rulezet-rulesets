rule TTP_XOR_MULT_DOSStub_7fd2 {
  strings:
    $key_7fd2 = { 2b ba [2] 5f a2 [2] 18 a0 [2] 5f b1 [2] 11 bd [2] 1d b7 [2] 0a bc [2] 11 f2 [2] 2c }

  condition:
    any of them
}