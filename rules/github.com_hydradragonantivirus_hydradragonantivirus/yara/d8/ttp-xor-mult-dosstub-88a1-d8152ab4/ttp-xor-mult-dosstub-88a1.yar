rule TTP_XOR_MULT_DOSStub_88a1 {
  strings:
    $key_88a1 = { dc c9 [2] a8 d1 [2] ef d3 [2] a8 c2 [2] e6 ce [2] ea c4 [2] fd cf [2] e6 81 [2] db }

  condition:
    any of them
}