rule TTP_XOR_MULT_DOSStub_2ea1 {
  strings:
    $key_2ea1 = { 7a c9 [2] 0e d1 [2] 49 d3 [2] 0e c2 [2] 40 ce [2] 4c c4 [2] 5b cf [2] 40 81 [2] 7d }

  condition:
    any of them
}