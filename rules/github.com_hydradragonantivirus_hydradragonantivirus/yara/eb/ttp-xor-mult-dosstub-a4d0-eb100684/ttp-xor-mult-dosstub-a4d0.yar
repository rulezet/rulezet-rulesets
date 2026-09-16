rule TTP_XOR_MULT_DOSStub_a4d0 {
  strings:
    $key_a4d0 = { f0 b8 [2] 84 a0 [2] c3 a2 [2] 84 b3 [2] ca bf [2] c6 b5 [2] d1 be [2] ca f0 [2] f7 }

  condition:
    any of them
}