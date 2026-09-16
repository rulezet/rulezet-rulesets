rule TTP_XOR_MULT_DOSStub_a7d2 {
  strings:
    $key_a7d2 = { f3 ba [2] 87 a2 [2] c0 a0 [2] 87 b1 [2] c9 bd [2] c5 b7 [2] d2 bc [2] c9 f2 [2] f4 }

  condition:
    any of them
}