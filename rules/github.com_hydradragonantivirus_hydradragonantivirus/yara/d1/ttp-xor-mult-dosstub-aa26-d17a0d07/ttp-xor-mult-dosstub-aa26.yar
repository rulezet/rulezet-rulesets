rule TTP_XOR_MULT_DOSStub_aa26 {
  strings:
    $key_aa26 = { fe 4e [2] 8a 56 [2] cd 54 [2] 8a 45 [2] c4 49 [2] c8 43 [2] df 48 [2] c4 06 [2] f9 }

  condition:
    any of them
}