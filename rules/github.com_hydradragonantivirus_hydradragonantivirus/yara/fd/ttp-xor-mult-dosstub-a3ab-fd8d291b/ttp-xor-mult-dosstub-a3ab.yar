rule TTP_XOR_MULT_DOSStub_a3ab {
  strings:
    $key_a3ab = { f7 c3 [2] 83 db [2] c4 d9 [2] 83 c8 [2] cd c4 [2] c1 ce [2] d6 c5 [2] cd 8b [2] f0 }

  condition:
    any of them
}