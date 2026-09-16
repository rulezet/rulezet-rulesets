rule TTP_XOR_MULT_DOSStub_f487 {
  strings:
    $key_f487 = { a0 ef [2] d4 f7 [2] 93 f5 [2] d4 e4 [2] 9a e8 [2] 96 e2 [2] 81 e9 [2] 9a a7 [2] a7 }

  condition:
    any of them
}