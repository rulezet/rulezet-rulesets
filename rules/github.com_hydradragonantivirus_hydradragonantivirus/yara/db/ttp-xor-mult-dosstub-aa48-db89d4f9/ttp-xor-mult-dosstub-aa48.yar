rule TTP_XOR_MULT_DOSStub_aa48 {
  strings:
    $key_aa48 = { fe 20 [2] 8a 38 [2] cd 3a [2] 8a 2b [2] c4 27 [2] c8 2d [2] df 26 [2] c4 68 [2] f9 }

  condition:
    any of them
}