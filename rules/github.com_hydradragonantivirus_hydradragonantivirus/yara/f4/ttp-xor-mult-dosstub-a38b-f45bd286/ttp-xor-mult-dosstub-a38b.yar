rule TTP_XOR_MULT_DOSStub_a38b {
  strings:
    $key_a38b = { f7 e3 [2] 83 fb [2] c4 f9 [2] 83 e8 [2] cd e4 [2] c1 ee [2] d6 e5 [2] cd ab [2] f0 }

  condition:
    any of them
}