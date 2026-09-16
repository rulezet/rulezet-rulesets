rule TTP_XOR_MULT_DOSStub_0987 {
  strings:
    $key_0987 = { 5d ef [2] 29 f7 [2] 6e f5 [2] 29 e4 [2] 67 e8 [2] 6b e2 [2] 7c e9 [2] 67 a7 [2] 5a }

  condition:
    any of them
}