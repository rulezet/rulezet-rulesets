rule TTP_XOR_MULT_DOSStub_0ea1 {
  strings:
    $key_0ea1 = { 5a c9 [2] 2e d1 [2] 69 d3 [2] 2e c2 [2] 60 ce [2] 6c c4 [2] 7b cf [2] 60 81 [2] 5d }

  condition:
    any of them
}