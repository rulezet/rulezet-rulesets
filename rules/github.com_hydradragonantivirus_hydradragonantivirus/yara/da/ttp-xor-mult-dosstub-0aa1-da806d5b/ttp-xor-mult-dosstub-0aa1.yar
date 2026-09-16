rule TTP_XOR_MULT_DOSStub_0aa1 {
  strings:
    $key_0aa1 = { 5e c9 [2] 2a d1 [2] 6d d3 [2] 2a c2 [2] 64 ce [2] 68 c4 [2] 7f cf [2] 64 81 [2] 59 }

  condition:
    any of them
}