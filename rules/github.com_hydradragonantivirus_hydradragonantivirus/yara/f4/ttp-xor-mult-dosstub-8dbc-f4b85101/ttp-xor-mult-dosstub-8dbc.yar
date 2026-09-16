rule TTP_XOR_MULT_DOSStub_8dbc {
  strings:
    $key_8dbc = { d9 d4 [2] ad cc [2] ea ce [2] ad df [2] e3 d3 [2] ef d9 [2] f8 d2 [2] e3 9c [2] de }

  condition:
    any of them
}