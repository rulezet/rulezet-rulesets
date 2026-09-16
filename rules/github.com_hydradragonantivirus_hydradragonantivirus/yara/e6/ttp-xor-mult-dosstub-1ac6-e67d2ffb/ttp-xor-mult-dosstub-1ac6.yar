rule TTP_XOR_MULT_DOSStub_1ac6 {
  strings:
    $key_1ac6 = { 4e ae [2] 3a b6 [2] 7d b4 [2] 3a a5 [2] 74 a9 [2] 78 a3 [2] 6f a8 [2] 74 e6 [2] 49 }

  condition:
    any of them
}