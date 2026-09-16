rule TTP_XOR_MULT_DOSStub_f180 {
  strings:
    $key_f180 = { a5 e8 [2] d1 f0 [2] 96 f2 [2] d1 e3 [2] 9f ef [2] 93 e5 [2] 84 ee [2] 9f a0 [2] a2 }

  condition:
    any of them
}