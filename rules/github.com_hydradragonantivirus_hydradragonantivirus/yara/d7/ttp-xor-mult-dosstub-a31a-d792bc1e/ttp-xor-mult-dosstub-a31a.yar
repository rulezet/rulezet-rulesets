rule TTP_XOR_MULT_DOSStub_a31a {
  strings:
    $key_a31a = { f7 72 [2] 83 6a [2] c4 68 [2] 83 79 [2] cd 75 [2] c1 7f [2] d6 74 [2] cd 3a [2] f0 }

  condition:
    any of them
}