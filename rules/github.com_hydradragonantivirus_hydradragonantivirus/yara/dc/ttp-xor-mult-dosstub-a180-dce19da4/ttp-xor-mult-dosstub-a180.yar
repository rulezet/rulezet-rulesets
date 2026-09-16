rule TTP_XOR_MULT_DOSStub_a180 {
  strings:
    $key_a180 = { f5 e8 [2] 81 f0 [2] c6 f2 [2] 81 e3 [2] cf ef [2] c3 e5 [2] d4 ee [2] cf a0 [2] f2 }

  condition:
    any of them
}