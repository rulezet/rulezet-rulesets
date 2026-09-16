rule TTP_XOR_MULT_DOSStub_a3f0 {
  strings:
    $key_a3f0 = { f7 98 [2] 83 80 [2] c4 82 [2] 83 93 [2] cd 9f [2] c1 95 [2] d6 9e [2] cd d0 [2] f0 }

  condition:
    any of them
}