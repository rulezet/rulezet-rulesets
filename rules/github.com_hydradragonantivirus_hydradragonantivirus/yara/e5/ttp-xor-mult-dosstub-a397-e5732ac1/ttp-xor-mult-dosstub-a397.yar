rule TTP_XOR_MULT_DOSStub_a397 {
  strings:
    $key_a397 = { f7 ff [2] 83 e7 [2] c4 e5 [2] 83 f4 [2] cd f8 [2] c1 f2 [2] d6 f9 [2] cd b7 [2] f0 }

  condition:
    any of them
}