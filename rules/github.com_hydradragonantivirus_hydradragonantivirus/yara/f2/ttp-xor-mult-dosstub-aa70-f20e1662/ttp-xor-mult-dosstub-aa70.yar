rule TTP_XOR_MULT_DOSStub_aa70 {
  strings:
    $key_aa70 = { fe 18 [2] 8a 00 [2] cd 02 [2] 8a 13 [2] c4 1f [2] c8 15 [2] df 1e [2] c4 50 [2] f9 }

  condition:
    any of them
}