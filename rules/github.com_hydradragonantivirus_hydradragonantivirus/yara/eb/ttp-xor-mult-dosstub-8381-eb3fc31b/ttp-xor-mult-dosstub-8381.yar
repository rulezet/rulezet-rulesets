rule TTP_XOR_MULT_DOSStub_8381 {
  strings:
    $key_8381 = { d7 e9 [2] a3 f1 [2] e4 f3 [2] a3 e2 [2] ed ee [2] e1 e4 [2] f6 ef [2] ed a1 [2] d0 }

  condition:
    any of them
}