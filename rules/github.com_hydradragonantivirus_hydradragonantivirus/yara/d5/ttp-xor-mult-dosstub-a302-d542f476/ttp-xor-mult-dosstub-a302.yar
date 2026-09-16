rule TTP_XOR_MULT_DOSStub_a302 {
  strings:
    $key_a302 = { f7 6a [2] 83 72 [2] c4 70 [2] 83 61 [2] cd 6d [2] c1 67 [2] d6 6c [2] cd 22 [2] f0 }

  condition:
    any of them
}