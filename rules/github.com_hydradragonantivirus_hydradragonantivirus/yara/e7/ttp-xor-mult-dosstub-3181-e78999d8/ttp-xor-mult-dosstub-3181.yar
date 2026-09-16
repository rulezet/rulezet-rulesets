rule TTP_XOR_MULT_DOSStub_3181 {
  strings:
    $key_3181 = { 65 e9 [2] 11 f1 [2] 56 f3 [2] 11 e2 [2] 5f ee [2] 53 e4 [2] 44 ef [2] 5f a1 [2] 62 }

  condition:
    any of them
}