rule TTP_XOR_MULT_DOSStub_1987 {
  strings:
    $key_1987 = { 4d ef [2] 39 f7 [2] 7e f5 [2] 39 e4 [2] 77 e8 [2] 7b e2 [2] 6c e9 [2] 77 a7 [2] 4a }

  condition:
    any of them
}