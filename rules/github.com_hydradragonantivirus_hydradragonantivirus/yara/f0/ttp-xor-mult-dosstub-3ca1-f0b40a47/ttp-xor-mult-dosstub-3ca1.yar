rule TTP_XOR_MULT_DOSStub_3ca1 {
  strings:
    $key_3ca1 = { 68 c9 [2] 1c d1 [2] 5b d3 [2] 1c c2 [2] 52 ce [2] 5e c4 [2] 49 cf [2] 52 81 [2] 6f }

  condition:
    any of them
}