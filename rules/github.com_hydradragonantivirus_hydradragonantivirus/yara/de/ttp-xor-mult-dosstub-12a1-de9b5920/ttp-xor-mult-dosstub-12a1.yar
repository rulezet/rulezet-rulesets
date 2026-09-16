rule TTP_XOR_MULT_DOSStub_12a1 {
  strings:
    $key_12a1 = { 46 c9 [2] 32 d1 [2] 75 d3 [2] 32 c2 [2] 7c ce [2] 70 c4 [2] 67 cf [2] 7c 81 [2] 41 }

  condition:
    any of them
}