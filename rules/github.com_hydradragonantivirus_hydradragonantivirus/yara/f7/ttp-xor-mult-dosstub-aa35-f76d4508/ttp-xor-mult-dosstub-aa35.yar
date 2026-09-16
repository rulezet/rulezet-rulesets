rule TTP_XOR_MULT_DOSStub_aa35 {
  strings:
    $key_aa35 = { fe 5d [2] 8a 45 [2] cd 47 [2] 8a 56 [2] c4 5a [2] c8 50 [2] df 5b [2] c4 15 [2] f9 }

  condition:
    any of them
}