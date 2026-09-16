rule TTP_XOR_MULT_DOSStub_e181 {
  strings:
    $key_e181 = { b5 e9 [2] c1 f1 [2] 86 f3 [2] c1 e2 [2] 8f ee [2] 83 e4 [2] 94 ef [2] 8f a1 [2] b2 }

  condition:
    any of them
}