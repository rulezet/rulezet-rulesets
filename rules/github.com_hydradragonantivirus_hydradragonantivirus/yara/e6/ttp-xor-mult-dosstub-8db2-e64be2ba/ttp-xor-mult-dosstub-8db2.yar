rule TTP_XOR_MULT_DOSStub_8db2 {
  strings:
    $key_8db2 = { d9 da [2] ad c2 [2] ea c0 [2] ad d1 [2] e3 dd [2] ef d7 [2] f8 dc [2] e3 92 [2] de }

  condition:
    any of them
}