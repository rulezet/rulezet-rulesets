rule TTP_XOR_MULT_DOSStub_aab5 {
  strings:
    $key_aab5 = { fe dd [2] 8a c5 [2] cd c7 [2] 8a d6 [2] c4 da [2] c8 d0 [2] df db [2] c4 95 [2] f9 }

  condition:
    any of them
}