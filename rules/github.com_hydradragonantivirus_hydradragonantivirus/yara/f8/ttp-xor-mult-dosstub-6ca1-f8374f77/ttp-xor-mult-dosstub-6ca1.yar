rule TTP_XOR_MULT_DOSStub_6ca1 {
  strings:
    $key_6ca1 = { 38 c9 [2] 4c d1 [2] 0b d3 [2] 4c c2 [2] 02 ce [2] 0e c4 [2] 19 cf [2] 02 81 [2] 3f }

  condition:
    any of them
}