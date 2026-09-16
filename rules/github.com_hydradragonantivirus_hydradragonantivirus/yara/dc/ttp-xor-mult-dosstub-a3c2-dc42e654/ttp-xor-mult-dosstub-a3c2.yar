rule TTP_XOR_MULT_DOSStub_a3c2 {
  strings:
    $key_a3c2 = { f7 aa [2] 83 b2 [2] c4 b0 [2] 83 a1 [2] cd ad [2] c1 a7 [2] d6 ac [2] cd e2 [2] f0 }

  condition:
    any of them
}