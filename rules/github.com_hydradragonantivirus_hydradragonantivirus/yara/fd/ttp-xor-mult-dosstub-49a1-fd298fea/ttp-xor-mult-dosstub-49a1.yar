rule TTP_XOR_MULT_DOSStub_49a1 {
  strings:
    $key_49a1 = { 1d c9 [2] 69 d1 [2] 2e d3 [2] 69 c2 [2] 27 ce [2] 2b c4 [2] 3c cf [2] 27 81 [2] 1a }

  condition:
    any of them
}