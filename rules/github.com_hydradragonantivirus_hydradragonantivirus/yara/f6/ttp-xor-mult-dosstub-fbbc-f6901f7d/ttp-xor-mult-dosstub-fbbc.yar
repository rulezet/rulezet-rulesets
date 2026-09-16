rule TTP_XOR_MULT_DOSStub_fbbc {
  strings:
    $key_fbbc = { af d4 [2] db cc [2] 9c ce [2] db df [2] 95 d3 [2] 99 d9 [2] 8e d2 [2] 95 9c [2] a8 }

  condition:
    any of them
}