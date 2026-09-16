rule TTP_XOR_MULT_DOSStub_aa12 {
  strings:
    $key_aa12 = { fe 7a [2] 8a 62 [2] cd 60 [2] 8a 71 [2] c4 7d [2] c8 77 [2] df 7c [2] c4 32 [2] f9 }

  condition:
    any of them
}