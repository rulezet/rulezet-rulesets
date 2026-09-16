rule TTP_XOR_MULT_DOSStub_aa54 {
  strings:
    $key_aa54 = { fe 3c [2] 8a 24 [2] cd 26 [2] 8a 37 [2] c4 3b [2] c8 31 [2] df 3a [2] c4 74 [2] f9 }

  condition:
    any of them
}