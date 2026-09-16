rule TTP_XOR_MULT_DOSStub_6aa1 {
  strings:
    $key_6aa1 = { 3e c9 [2] 4a d1 [2] 0d d3 [2] 4a c2 [2] 04 ce [2] 08 c4 [2] 1f cf [2] 04 81 [2] 39 }

  condition:
    any of them
}