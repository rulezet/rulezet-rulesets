rule TTP_XOR_MULT_DOSStub_a358 {
  strings:
    $key_a358 = { f7 30 [2] 83 28 [2] c4 2a [2] 83 3b [2] cd 37 [2] c1 3d [2] d6 36 [2] cd 78 [2] f0 }

  condition:
    any of them
}