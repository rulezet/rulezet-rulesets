rule TTP_XOR_MULT_DOSStub_a3c1 {
  strings:
    $key_a3c1 = { f7 a9 [2] 83 b1 [2] c4 b3 [2] 83 a2 [2] cd ae [2] c1 a4 [2] d6 af [2] cd e1 [2] f0 }

  condition:
    any of them
}