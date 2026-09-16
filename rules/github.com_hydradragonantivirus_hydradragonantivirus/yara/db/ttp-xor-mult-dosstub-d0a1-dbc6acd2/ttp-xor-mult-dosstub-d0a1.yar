rule TTP_XOR_MULT_DOSStub_d0a1 {
  strings:
    $key_d0a1 = { 84 c9 [2] f0 d1 [2] b7 d3 [2] f0 c2 [2] be ce [2] b2 c4 [2] a5 cf [2] be 81 [2] 83 }

  condition:
    any of them
}