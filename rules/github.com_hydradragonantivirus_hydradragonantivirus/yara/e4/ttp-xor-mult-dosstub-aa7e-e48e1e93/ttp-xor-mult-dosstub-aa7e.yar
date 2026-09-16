rule TTP_XOR_MULT_DOSStub_aa7e {
  strings:
    $key_aa7e = { fe 16 [2] 8a 0e [2] cd 0c [2] 8a 1d [2] c4 11 [2] c8 1b [2] df 10 [2] c4 5e [2] f9 }

  condition:
    any of them
}