rule TTP_XOR_MULT_DOSStub_a379 {
  strings:
    $key_a379 = { f7 11 [2] 83 09 [2] c4 0b [2] 83 1a [2] cd 16 [2] c1 1c [2] d6 17 [2] cd 59 [2] f0 }

  condition:
    any of them
}