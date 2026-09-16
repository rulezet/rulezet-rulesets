rule TTP_XOR_MULT_DOSStub_e287 {
  strings:
    $key_e287 = { b6 ef [2] c2 f7 [2] 85 f5 [2] c2 e4 [2] 8c e8 [2] 80 e2 [2] 97 e9 [2] 8c a7 [2] b1 }

  condition:
    any of them
}