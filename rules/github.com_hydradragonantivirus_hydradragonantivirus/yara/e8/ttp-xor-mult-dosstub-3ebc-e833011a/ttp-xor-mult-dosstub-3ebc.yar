rule TTP_XOR_MULT_DOSStub_3ebc {
  strings:
    $key_3ebc = { 6a d4 [2] 1e cc [2] 59 ce [2] 1e df [2] 50 d3 [2] 5c d9 [2] 4b d2 [2] 50 9c [2] 6d }

  condition:
    any of them
}