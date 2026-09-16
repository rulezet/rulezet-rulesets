rule TTP_XOR_MULT_DOSStub_a352 {
  strings:
    $key_a352 = { f7 3a [2] 83 22 [2] c4 20 [2] 83 31 [2] cd 3d [2] c1 37 [2] d6 3c [2] cd 72 [2] f0 }

  condition:
    any of them
}