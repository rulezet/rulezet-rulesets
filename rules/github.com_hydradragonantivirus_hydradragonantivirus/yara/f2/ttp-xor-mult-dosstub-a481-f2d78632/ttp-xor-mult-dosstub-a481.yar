rule TTP_XOR_MULT_DOSStub_a481 {
  strings:
    $key_a481 = { f0 e9 [2] 84 f1 [2] c3 f3 [2] 84 e2 [2] ca ee [2] c6 e4 [2] d1 ef [2] ca a1 [2] f7 }

  condition:
    any of them
}