rule TTP_XOR_MULT_DOSStub_e081 {
  strings:
    $key_e081 = { b4 e9 [2] c0 f1 [2] 87 f3 [2] c0 e2 [2] 8e ee [2] 82 e4 [2] 95 ef [2] 8e a1 [2] b3 }

  condition:
    any of them
}