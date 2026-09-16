rule TTP_XOR_MULT_DOSStub_a33b {
  strings:
    $key_a33b = { f7 53 [2] 83 4b [2] c4 49 [2] 83 58 [2] cd 54 [2] c1 5e [2] d6 55 [2] cd 1b [2] f0 }

  condition:
    any of them
}