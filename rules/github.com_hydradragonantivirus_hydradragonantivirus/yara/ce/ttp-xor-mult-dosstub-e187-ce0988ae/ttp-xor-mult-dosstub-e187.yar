rule TTP_XOR_MULT_DOSStub_e187 {
  strings:
    $key_e187 = { b5 ef [2] c1 f7 [2] 86 f5 [2] c1 e4 [2] 8f e8 [2] 83 e2 [2] 94 e9 [2] 8f a7 [2] b2 }

  condition:
    any of them
}