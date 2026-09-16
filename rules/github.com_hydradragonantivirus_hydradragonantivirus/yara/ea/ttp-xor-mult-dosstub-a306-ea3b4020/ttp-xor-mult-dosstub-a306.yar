rule TTP_XOR_MULT_DOSStub_a306 {
  strings:
    $key_a306 = { f7 6e [2] 83 76 [2] c4 74 [2] 83 65 [2] cd 69 [2] c1 63 [2] d6 68 [2] cd 26 [2] f0 }

  condition:
    any of them
}