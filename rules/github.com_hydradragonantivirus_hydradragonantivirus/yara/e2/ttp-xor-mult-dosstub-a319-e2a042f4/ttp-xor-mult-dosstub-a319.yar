rule TTP_XOR_MULT_DOSStub_a319 {
  strings:
    $key_a319 = { f7 71 [2] 83 69 [2] c4 6b [2] 83 7a [2] cd 76 [2] c1 7c [2] d6 77 [2] cd 39 [2] f0 }

  condition:
    any of them
}