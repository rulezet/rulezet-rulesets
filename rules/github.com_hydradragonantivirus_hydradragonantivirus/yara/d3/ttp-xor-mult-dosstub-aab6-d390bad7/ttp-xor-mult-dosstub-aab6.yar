rule TTP_XOR_MULT_DOSStub_aab6 {
  strings:
    $key_aab6 = { fe de [2] 8a c6 [2] cd c4 [2] 8a d5 [2] c4 d9 [2] c8 d3 [2] df d8 [2] c4 96 [2] f9 }

  condition:
    any of them
}