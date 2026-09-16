rule TTP_XOR_MULT_DOSStub_aac9 {
  strings:
    $key_aac9 = { fe a1 [2] 8a b9 [2] cd bb [2] 8a aa [2] c4 a6 [2] c8 ac [2] df a7 [2] c4 e9 [2] f9 }

  condition:
    any of them
}