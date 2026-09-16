rule TTP_XOR_MULT_DOSStub_a34b {
  strings:
    $key_a34b = { f7 23 [2] 83 3b [2] c4 39 [2] 83 28 [2] cd 24 [2] c1 2e [2] d6 25 [2] cd 6b [2] f0 }

  condition:
    any of them
}