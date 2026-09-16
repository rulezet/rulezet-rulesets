rule TTP_XOR_MULT_DOSStub_4187 {
  strings:
    $key_4187 = { 15 ef [2] 61 f7 [2] 26 f5 [2] 61 e4 [2] 2f e8 [2] 23 e2 [2] 34 e9 [2] 2f a7 [2] 12 }

  condition:
    any of them
}