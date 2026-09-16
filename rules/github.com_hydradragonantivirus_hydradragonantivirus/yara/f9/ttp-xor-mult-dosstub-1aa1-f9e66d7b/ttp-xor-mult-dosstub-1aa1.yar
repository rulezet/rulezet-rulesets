rule TTP_XOR_MULT_DOSStub_1aa1 {
  strings:
    $key_1aa1 = { 4e c9 [2] 3a d1 [2] 7d d3 [2] 3a c2 [2] 74 ce [2] 78 c4 [2] 6f cf [2] 74 81 [2] 49 }

  condition:
    any of them
}