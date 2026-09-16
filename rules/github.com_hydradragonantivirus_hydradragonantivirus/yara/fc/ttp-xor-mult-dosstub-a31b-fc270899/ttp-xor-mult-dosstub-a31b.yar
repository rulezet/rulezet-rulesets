rule TTP_XOR_MULT_DOSStub_a31b {
  strings:
    $key_a31b = { f7 73 [2] 83 6b [2] c4 69 [2] 83 78 [2] cd 74 [2] c1 7e [2] d6 75 [2] cd 3b [2] f0 }

  condition:
    any of them
}