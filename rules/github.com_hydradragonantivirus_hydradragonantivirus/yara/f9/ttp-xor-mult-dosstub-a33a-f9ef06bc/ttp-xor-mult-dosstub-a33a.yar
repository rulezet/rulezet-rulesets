rule TTP_XOR_MULT_DOSStub_a33a {
  strings:
    $key_a33a = { f7 52 [2] 83 4a [2] c4 48 [2] 83 59 [2] cd 55 [2] c1 5f [2] d6 54 [2] cd 1a [2] f0 }

  condition:
    any of them
}