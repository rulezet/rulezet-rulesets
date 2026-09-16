rule TTP_XOR_MULT_DOSStub_a35a {
  strings:
    $key_a35a = { f7 32 [2] 83 2a [2] c4 28 [2] 83 39 [2] cd 35 [2] c1 3f [2] d6 34 [2] cd 7a [2] f0 }

  condition:
    any of them
}