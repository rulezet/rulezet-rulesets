rule TTP_XOR_MULT_DOSStub_aaa3 {
  strings:
    $key_aaa3 = { fe cb [2] 8a d3 [2] cd d1 [2] 8a c0 [2] c4 cc [2] c8 c6 [2] df cd [2] c4 83 [2] f9 }

  condition:
    any of them
}