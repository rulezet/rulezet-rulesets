rule TTP_XOR_MULT_DOSStub_aaa6 {
  strings:
    $key_aaa6 = { fe ce [2] 8a d6 [2] cd d4 [2] 8a c5 [2] c4 c9 [2] c8 c3 [2] df c8 [2] c4 86 [2] f9 }

  condition:
    any of them
}