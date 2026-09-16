rule TTP_XOR_MULT_DOSStub_aa38 {
  strings:
    $key_aa38 = { fe 50 [2] 8a 48 [2] cd 4a [2] 8a 5b [2] c4 57 [2] c8 5d [2] df 56 [2] c4 18 [2] f9 }

  condition:
    any of them
}