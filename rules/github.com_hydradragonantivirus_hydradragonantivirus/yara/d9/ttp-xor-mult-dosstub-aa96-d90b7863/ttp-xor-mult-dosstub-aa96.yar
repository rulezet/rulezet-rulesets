rule TTP_XOR_MULT_DOSStub_aa96 {
  strings:
    $key_aa96 = { fe fe [2] 8a e6 [2] cd e4 [2] 8a f5 [2] c4 f9 [2] c8 f3 [2] df f8 [2] c4 b6 [2] f9 }

  condition:
    any of them
}