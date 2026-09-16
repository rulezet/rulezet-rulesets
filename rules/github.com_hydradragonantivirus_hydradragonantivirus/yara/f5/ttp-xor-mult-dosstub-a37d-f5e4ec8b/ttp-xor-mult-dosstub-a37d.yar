rule TTP_XOR_MULT_DOSStub_a37d {
  strings:
    $key_a37d = { f7 15 [2] 83 0d [2] c4 0f [2] 83 1e [2] cd 12 [2] c1 18 [2] d6 13 [2] cd 5d [2] f0 }

  condition:
    any of them
}