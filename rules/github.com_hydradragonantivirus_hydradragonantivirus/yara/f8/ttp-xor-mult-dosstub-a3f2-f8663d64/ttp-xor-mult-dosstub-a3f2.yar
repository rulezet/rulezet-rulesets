rule TTP_XOR_MULT_DOSStub_a3f2 {
  strings:
    $key_a3f2 = { f7 9a [2] 83 82 [2] c4 80 [2] 83 91 [2] cd 9d [2] c1 97 [2] d6 9c [2] cd d2 [2] f0 }

  condition:
    any of them
}