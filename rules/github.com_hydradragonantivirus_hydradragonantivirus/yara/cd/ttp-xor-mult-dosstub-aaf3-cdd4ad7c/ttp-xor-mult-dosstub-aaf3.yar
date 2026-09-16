rule TTP_XOR_MULT_DOSStub_aaf3 {
  strings:
    $key_aaf3 = { fe 9b [2] 8a 83 [2] cd 81 [2] 8a 90 [2] c4 9c [2] c8 96 [2] df 9d [2] c4 d3 [2] f9 }

  condition:
    any of them
}