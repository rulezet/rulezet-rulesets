rule TTP_XOR_MULT_DOSStub_2dbc {
  strings:
    $key_2dbc = { 79 d4 [2] 0d cc [2] 4a ce [2] 0d df [2] 43 d3 [2] 4f d9 [2] 58 d2 [2] 43 9c [2] 7e }

  condition:
    any of them
}