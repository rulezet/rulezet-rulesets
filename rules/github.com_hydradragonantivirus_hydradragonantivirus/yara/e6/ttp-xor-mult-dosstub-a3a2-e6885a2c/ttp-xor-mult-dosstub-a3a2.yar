rule TTP_XOR_MULT_DOSStub_a3a2 {
  strings:
    $key_a3a2 = { f7 ca [2] 83 d2 [2] c4 d0 [2] 83 c1 [2] cd cd [2] c1 c7 [2] d6 cc [2] cd 82 [2] f0 }

  condition:
    any of them
}