rule TTP_XOR_MULT_DOSStub_aac7 {
  strings:
    $key_aac7 = { fe af [2] 8a b7 [2] cd b5 [2] 8a a4 [2] c4 a8 [2] c8 a2 [2] df a9 [2] c4 e7 [2] f9 }

  condition:
    any of them
}