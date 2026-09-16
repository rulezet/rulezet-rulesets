rule TTP_XOR_MULT_DOSStub_a3a3 {
  strings:
    $key_a3a3 = { f7 cb [2] 83 d3 [2] c4 d1 [2] 83 c0 [2] cd cc [2] c1 c6 [2] d6 cd [2] cd 83 [2] f0 }

  condition:
    any of them
}