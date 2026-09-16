rule TTP_XOR_MULT_DOSStub_aa33 {
  strings:
    $key_aa33 = { fe 5b [2] 8a 43 [2] cd 41 [2] 8a 50 [2] c4 5c [2] c8 56 [2] df 5d [2] c4 13 [2] f9 }

  condition:
    any of them
}