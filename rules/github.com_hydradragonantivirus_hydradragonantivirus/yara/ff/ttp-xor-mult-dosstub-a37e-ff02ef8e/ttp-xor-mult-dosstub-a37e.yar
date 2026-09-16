rule TTP_XOR_MULT_DOSStub_a37e {
  strings:
    $key_a37e = { f7 16 [2] 83 0e [2] c4 0c [2] 83 1d [2] cd 11 [2] c1 1b [2] d6 10 [2] cd 5e [2] f0 }

  condition:
    any of them
}