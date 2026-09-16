rule TTP_XOR_MULT_DOSStub_a3da {
  strings:
    $key_a3da = { f7 b2 [2] 83 aa [2] c4 a8 [2] 83 b9 [2] cd b5 [2] c1 bf [2] d6 b4 [2] cd fa [2] f0 }

  condition:
    any of them
}