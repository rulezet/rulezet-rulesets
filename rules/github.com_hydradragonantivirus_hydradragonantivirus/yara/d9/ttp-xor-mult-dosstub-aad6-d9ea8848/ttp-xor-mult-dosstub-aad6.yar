rule TTP_XOR_MULT_DOSStub_aad6 {
  strings:
    $key_aad6 = { fe be [2] 8a a6 [2] cd a4 [2] 8a b5 [2] c4 b9 [2] c8 b3 [2] df b8 [2] c4 f6 [2] f9 }

  condition:
    any of them
}