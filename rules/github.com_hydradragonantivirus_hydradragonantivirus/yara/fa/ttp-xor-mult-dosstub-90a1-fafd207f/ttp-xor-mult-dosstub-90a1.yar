rule TTP_XOR_MULT_DOSStub_90a1 {
  strings:
    $key_90a1 = { c4 c9 [2] b0 d1 [2] f7 d3 [2] b0 c2 [2] fe ce [2] f2 c4 [2] e5 cf [2] fe 81 [2] c3 }

  condition:
    any of them
}