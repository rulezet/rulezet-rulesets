rule TTP_XOR_MULT_DOSStub_a35d {
  strings:
    $key_a35d = { f7 35 [2] 83 2d [2] c4 2f [2] 83 3e [2] cd 32 [2] c1 38 [2] d6 33 [2] cd 7d [2] f0 }

  condition:
    any of them
}