rule TTP_XOR_MULT_DOSStub_aad7 {
  strings:
    $key_aad7 = { fe bf [2] 8a a7 [2] cd a5 [2] 8a b4 [2] c4 b8 [2] c8 b2 [2] df b9 [2] c4 f7 [2] f9 }

  condition:
    any of them
}