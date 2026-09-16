rule TTP_XOR_MULT_DOSStub_6ebc {
  strings:
    $key_6ebc = { 3a d4 [2] 4e cc [2] 09 ce [2] 4e df [2] 00 d3 [2] 0c d9 [2] 1b d2 [2] 00 9c [2] 3d }

  condition:
    any of them
}