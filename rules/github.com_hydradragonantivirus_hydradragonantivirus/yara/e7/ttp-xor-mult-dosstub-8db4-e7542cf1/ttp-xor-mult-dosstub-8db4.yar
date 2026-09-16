rule TTP_XOR_MULT_DOSStub_8db4 {
  strings:
    $key_8db4 = { d9 dc [2] ad c4 [2] ea c6 [2] ad d7 [2] e3 db [2] ef d1 [2] f8 da [2] e3 94 [2] de }

  condition:
    any of them
}