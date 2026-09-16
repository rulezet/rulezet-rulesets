rule TTP_XOR_MULT_DOSStub_aa73 {
  strings:
    $key_aa73 = { fe 1b [2] 8a 03 [2] cd 01 [2] 8a 10 [2] c4 1c [2] c8 16 [2] df 1d [2] c4 53 [2] f9 }

  condition:
    any of them
}