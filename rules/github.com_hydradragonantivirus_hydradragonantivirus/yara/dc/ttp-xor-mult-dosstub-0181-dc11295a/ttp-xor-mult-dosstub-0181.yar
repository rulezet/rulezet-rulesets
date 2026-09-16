rule TTP_XOR_MULT_DOSStub_0181 {
  strings:
    $key_0181 = { 55 e9 [2] 21 f1 [2] 66 f3 [2] 21 e2 [2] 6f ee [2] 63 e4 [2] 74 ef [2] 6f a1 [2] 52 }

  condition:
    any of them
}