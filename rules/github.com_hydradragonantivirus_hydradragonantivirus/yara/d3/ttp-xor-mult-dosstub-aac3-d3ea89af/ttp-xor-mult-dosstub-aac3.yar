rule TTP_XOR_MULT_DOSStub_aac3 {
  strings:
    $key_aac3 = { fe ab [2] 8a b3 [2] cd b1 [2] 8a a0 [2] c4 ac [2] c8 a6 [2] df ad [2] c4 e3 [2] f9 }

  condition:
    any of them
}