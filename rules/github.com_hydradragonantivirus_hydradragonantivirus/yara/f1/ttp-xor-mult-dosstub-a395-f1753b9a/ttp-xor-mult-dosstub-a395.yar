rule TTP_XOR_MULT_DOSStub_a395 {
  strings:
    $key_a395 = { f7 fd [2] 83 e5 [2] c4 e7 [2] 83 f6 [2] cd fa [2] c1 f0 [2] d6 fb [2] cd b5 [2] f0 }

  condition:
    any of them
}