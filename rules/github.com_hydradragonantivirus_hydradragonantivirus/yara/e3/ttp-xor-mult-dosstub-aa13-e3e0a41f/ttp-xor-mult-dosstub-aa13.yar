rule TTP_XOR_MULT_DOSStub_aa13 {
  strings:
    $key_aa13 = { fe 7b [2] 8a 63 [2] cd 61 [2] 8a 70 [2] c4 7c [2] c8 76 [2] df 7d [2] c4 33 [2] f9 }

  condition:
    any of them
}