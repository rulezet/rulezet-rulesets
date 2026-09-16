rule TTP_XOR_MULT_DOSStub_aa32 {
  strings:
    $key_aa32 = { fe 5a [2] 8a 42 [2] cd 40 [2] 8a 51 [2] c4 5d [2] c8 57 [2] df 5c [2] c4 12 [2] f9 }

  condition:
    any of them
}