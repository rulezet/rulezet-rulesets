rule TTP_XOR_MULT_DOSStub_aae2 {
  strings:
    $key_aae2 = { fe 8a [2] 8a 92 [2] cd 90 [2] 8a 81 [2] c4 8d [2] c8 87 [2] df 8c [2] c4 c2 [2] f9 }

  condition:
    any of them
}