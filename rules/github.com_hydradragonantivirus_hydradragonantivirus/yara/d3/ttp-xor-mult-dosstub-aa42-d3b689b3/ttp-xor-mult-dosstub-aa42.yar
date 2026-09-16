rule TTP_XOR_MULT_DOSStub_aa42 {
  strings:
    $key_aa42 = { fe 2a [2] 8a 32 [2] cd 30 [2] 8a 21 [2] c4 2d [2] c8 27 [2] df 2c [2] c4 62 [2] f9 }

  condition:
    any of them
}