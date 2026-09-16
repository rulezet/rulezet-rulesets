rule TTP_XOR_MULT_DOSStub_f480 {
  strings:
    $key_f480 = { a0 e8 [2] d4 f0 [2] 93 f2 [2] d4 e3 [2] 9a ef [2] 96 e5 [2] 81 ee [2] 9a a0 [2] a7 }

  condition:
    any of them
}