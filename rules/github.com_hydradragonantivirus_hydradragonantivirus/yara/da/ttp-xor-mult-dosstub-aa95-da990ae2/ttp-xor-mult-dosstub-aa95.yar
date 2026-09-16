rule TTP_XOR_MULT_DOSStub_aa95 {
  strings:
    $key_aa95 = { fe fd [2] 8a e5 [2] cd e7 [2] 8a f6 [2] c4 fa [2] c8 f0 [2] df fb [2] c4 b5 [2] f9 }

  condition:
    any of them
}