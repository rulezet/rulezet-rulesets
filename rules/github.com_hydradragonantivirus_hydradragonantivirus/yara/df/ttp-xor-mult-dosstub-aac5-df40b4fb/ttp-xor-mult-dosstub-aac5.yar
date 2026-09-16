rule TTP_XOR_MULT_DOSStub_aac5 {
  strings:
    $key_aac5 = { fe ad [2] 8a b5 [2] cd b7 [2] 8a a6 [2] c4 aa [2] c8 a0 [2] df ab [2] c4 e5 [2] f9 }

  condition:
    any of them
}