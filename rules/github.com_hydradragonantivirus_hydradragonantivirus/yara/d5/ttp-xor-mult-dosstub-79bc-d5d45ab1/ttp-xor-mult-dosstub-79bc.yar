rule TTP_XOR_MULT_DOSStub_79bc {
  strings:
    $key_79bc = { 2d d4 [2] 59 cc [2] 1e ce [2] 59 df [2] 17 d3 [2] 1b d9 [2] 0c d2 [2] 17 9c [2] 2a }

  condition:
    any of them
}