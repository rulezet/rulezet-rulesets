rule TTP_XOR_MULT_DOSStub_aaa5 {
  strings:
    $key_aaa5 = { fe cd [2] 8a d5 [2] cd d7 [2] 8a c6 [2] c4 ca [2] c8 c0 [2] df cb [2] c4 85 [2] f9 }

  condition:
    any of them
}