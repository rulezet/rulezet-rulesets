rule TTP_XOR_MULT_DOSStub_8da1 {
  strings:
    $key_8da1 = { d9 c9 [2] ad d1 [2] ea d3 [2] ad c2 [2] e3 ce [2] ef c4 [2] f8 cf [2] e3 81 [2] de }

  condition:
    any of them
}