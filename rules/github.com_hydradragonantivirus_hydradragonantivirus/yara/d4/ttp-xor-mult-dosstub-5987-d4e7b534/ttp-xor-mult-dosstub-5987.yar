rule TTP_XOR_MULT_DOSStub_5987 {
  strings:
    $key_5987 = { 0d ef [2] 79 f7 [2] 3e f5 [2] 79 e4 [2] 37 e8 [2] 3b e2 [2] 2c e9 [2] 37 a7 [2] 0a }

  condition:
    any of them
}