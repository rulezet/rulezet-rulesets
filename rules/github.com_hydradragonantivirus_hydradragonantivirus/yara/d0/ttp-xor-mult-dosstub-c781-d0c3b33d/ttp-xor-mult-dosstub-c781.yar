rule TTP_XOR_MULT_DOSStub_c781 {
  strings:
    $key_c781 = { 93 e9 [2] e7 f1 [2] a0 f3 [2] e7 e2 [2] a9 ee [2] a5 e4 [2] b2 ef [2] a9 a1 [2] 94 }

  condition:
    any of them
}