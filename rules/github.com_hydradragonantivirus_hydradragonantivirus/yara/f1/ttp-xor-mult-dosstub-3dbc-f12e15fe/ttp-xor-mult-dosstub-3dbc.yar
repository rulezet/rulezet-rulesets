rule TTP_XOR_MULT_DOSStub_3dbc {
  strings:
    $key_3dbc = { 69 d4 [2] 1d cc [2] 5a ce [2] 1d df [2] 53 d3 [2] 5f d9 [2] 48 d2 [2] 53 9c [2] 6e }

  condition:
    any of them
}