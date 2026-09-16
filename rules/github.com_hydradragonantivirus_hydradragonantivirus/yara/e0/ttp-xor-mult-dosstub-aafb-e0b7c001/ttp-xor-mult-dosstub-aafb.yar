rule TTP_XOR_MULT_DOSStub_aafb {
  strings:
    $key_aafb = { fe 93 [2] 8a 8b [2] cd 89 [2] 8a 98 [2] c4 94 [2] c8 9e [2] df 95 [2] c4 db [2] f9 }

  condition:
    any of them
}