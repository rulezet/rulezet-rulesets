rule TTP_XOR_MULT_DOSStub_5aa1 {
  strings:
    $key_5aa1 = { 0e c9 [2] 7a d1 [2] 3d d3 [2] 7a c2 [2] 34 ce [2] 38 c4 [2] 2f cf [2] 34 81 [2] 09 }

  condition:
    any of them
}