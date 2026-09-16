rule TTP_XOR_MULT_DOSStub_a3f1 {
  strings:
    $key_a3f1 = { f7 99 [2] 83 81 [2] c4 83 [2] 83 92 [2] cd 9e [2] c1 94 [2] d6 9f [2] cd d1 [2] f0 }

  condition:
    any of them
}