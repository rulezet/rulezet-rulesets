rule TTP_XOR_MULT_DOSStub_aad3 {
  strings:
    $key_aad3 = { fe bb [2] 8a a3 [2] cd a1 [2] 8a b0 [2] c4 bc [2] c8 b6 [2] df bd [2] c4 f3 [2] f9 }

  condition:
    any of them
}