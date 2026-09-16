rule TTP_XOR_MULT_DOSStub_4181 {
  strings:
    $key_4181 = { 15 e9 [2] 61 f1 [2] 26 f3 [2] 61 e2 [2] 2f ee [2] 23 e4 [2] 34 ef [2] 2f a1 [2] 12 }

  condition:
    any of them
}