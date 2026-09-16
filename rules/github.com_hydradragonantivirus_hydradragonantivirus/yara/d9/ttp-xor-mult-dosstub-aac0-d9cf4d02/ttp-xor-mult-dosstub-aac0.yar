rule TTP_XOR_MULT_DOSStub_aac0 {
  strings:
    $key_aac0 = { fe a8 [2] 8a b0 [2] cd b2 [2] 8a a3 [2] c4 af [2] c8 a5 [2] df ae [2] c4 e0 [2] f9 }

  condition:
    any of them
}