rule TTP_XOR_MULT_DOSStub_a3a6 {
  strings:
    $key_a3a6 = { f7 ce [2] 83 d6 [2] c4 d4 [2] 83 c5 [2] cd c9 [2] c1 c3 [2] d6 c8 [2] cd 86 [2] f0 }

  condition:
    any of them
}