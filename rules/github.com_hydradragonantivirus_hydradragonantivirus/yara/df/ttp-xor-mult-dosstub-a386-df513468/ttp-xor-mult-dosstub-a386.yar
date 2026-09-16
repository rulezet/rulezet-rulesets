rule TTP_XOR_MULT_DOSStub_a386 {
  strings:
    $key_a386 = { f7 ee [2] 83 f6 [2] c4 f4 [2] 83 e5 [2] cd e9 [2] c1 e3 [2] d6 e8 [2] cd a6 [2] f0 }

  condition:
    any of them
}