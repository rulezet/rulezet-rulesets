rule TTP_XOR_MULT_DOSStub_aa50 {
  strings:
    $key_aa50 = { fe 38 [2] 8a 20 [2] cd 22 [2] 8a 33 [2] c4 3f [2] c8 35 [2] df 3e [2] c4 70 [2] f9 }

  condition:
    any of them
}