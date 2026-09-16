rule TTP_XOR_MULT_DOSStub_aa49 {
  strings:
    $key_aa49 = { fe 21 [2] 8a 39 [2] cd 3b [2] 8a 2a [2] c4 26 [2] c8 2c [2] df 27 [2] c4 69 [2] f9 }

  condition:
    any of them
}