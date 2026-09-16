rule TTP_XOR_MULT_DOSStub_7aa1 {
  strings:
    $key_7aa1 = { 2e c9 [2] 5a d1 [2] 1d d3 [2] 5a c2 [2] 14 ce [2] 18 c4 [2] 0f cf [2] 14 81 [2] 29 }

  condition:
    any of them
}