rule TTP_XOR_MULT_DOSStub_5ebc {
  strings:
    $key_5ebc = { 0a d4 [2] 7e cc [2] 39 ce [2] 7e df [2] 30 d3 [2] 3c d9 [2] 2b d2 [2] 30 9c [2] 0d }

  condition:
    any of them
}