rule TTP_XOR_MULT_DOSStub_aa31 {
  strings:
    $key_aa31 = { fe 59 [2] 8a 41 [2] cd 43 [2] 8a 52 [2] c4 5e [2] c8 54 [2] df 5f [2] c4 11 [2] f9 }

  condition:
    any of them
}