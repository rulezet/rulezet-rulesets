rule TTP_XOR_MULT_DOSStub_aa71 {
  strings:
    $key_aa71 = { fe 19 [2] 8a 01 [2] cd 03 [2] 8a 12 [2] c4 1e [2] c8 14 [2] df 1f [2] c4 51 [2] f9 }

  condition:
    any of them
}