rule TTP_XOR_MULT_DOSStub_49a0 {
  strings:
    $key_49a0 = { 1d c8 [2] 69 d0 [2] 2e d2 [2] 69 c3 [2] 27 cf [2] 2b c5 [2] 3c ce [2] 27 80 [2] 1a }

  condition:
    any of them
}