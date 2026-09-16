rule TTP_XOR_MULT_DOSStub_a3f7 {
  strings:
    $key_a3f7 = { f7 9f [2] 83 87 [2] c4 85 [2] 83 94 [2] cd 98 [2] c1 92 [2] d6 99 [2] cd d7 [2] f0 }

  condition:
    any of them
}