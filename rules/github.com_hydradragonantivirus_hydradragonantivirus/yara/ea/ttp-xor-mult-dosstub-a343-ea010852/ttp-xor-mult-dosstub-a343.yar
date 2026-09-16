rule TTP_XOR_MULT_DOSStub_a343 {
  strings:
    $key_a343 = { f7 2b [2] 83 33 [2] c4 31 [2] 83 20 [2] cd 2c [2] c1 26 [2] d6 2d [2] cd 63 [2] f0 }

  condition:
    any of them
}