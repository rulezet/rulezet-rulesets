rule TTP_XOR_MULT_DOSStub_aa0e {
  strings:
    $key_aa0e = { fe 66 [2] 8a 7e [2] cd 7c [2] 8a 6d [2] c4 61 [2] c8 6b [2] df 60 [2] c4 2e [2] f9 }

  condition:
    any of them
}