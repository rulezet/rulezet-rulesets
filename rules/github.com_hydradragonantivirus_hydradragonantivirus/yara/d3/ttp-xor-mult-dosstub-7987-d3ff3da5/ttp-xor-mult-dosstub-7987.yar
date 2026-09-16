rule TTP_XOR_MULT_DOSStub_7987 {
  strings:
    $key_7987 = { 2d ef [2] 59 f7 [2] 1e f5 [2] 59 e4 [2] 17 e8 [2] 1b e2 [2] 0c e9 [2] 17 a7 [2] 2a }

  condition:
    any of them
}