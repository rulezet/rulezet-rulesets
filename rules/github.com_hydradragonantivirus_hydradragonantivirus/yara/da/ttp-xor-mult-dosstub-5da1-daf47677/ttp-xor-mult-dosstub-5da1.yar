rule TTP_XOR_MULT_DOSStub_5da1 {
  strings:
    $key_5da1 = { 09 c9 [2] 7d d1 [2] 3a d3 [2] 7d c2 [2] 33 ce [2] 3f c4 [2] 28 cf [2] 33 81 [2] 0e }

  condition:
    any of them
}