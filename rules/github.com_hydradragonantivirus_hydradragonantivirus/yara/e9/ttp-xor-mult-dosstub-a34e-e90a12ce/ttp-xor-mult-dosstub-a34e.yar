rule TTP_XOR_MULT_DOSStub_a34e {
  strings:
    $key_a34e = { f7 26 [2] 83 3e [2] c4 3c [2] 83 2d [2] cd 21 [2] c1 2b [2] d6 20 [2] cd 6e [2] f0 }

  condition:
    any of them
}