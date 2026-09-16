rule TTP_XOR_MULT_DOSStub_a3c3 {
  strings:
    $key_a3c3 = { f7 ab [2] 83 b3 [2] c4 b1 [2] 83 a0 [2] cd ac [2] c1 a6 [2] d6 ad [2] cd e3 [2] f0 }

  condition:
    any of them
}