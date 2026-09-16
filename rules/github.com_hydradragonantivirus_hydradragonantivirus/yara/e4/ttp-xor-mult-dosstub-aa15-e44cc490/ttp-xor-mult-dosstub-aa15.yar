rule TTP_XOR_MULT_DOSStub_aa15 {
  strings:
    $key_aa15 = { fe 7d [2] 8a 65 [2] cd 67 [2] 8a 76 [2] c4 7a [2] c8 70 [2] df 7b [2] c4 35 [2] f9 }

  condition:
    any of them
}